package remotecache

import (
	"context"
	"log/slog"
	"math"
	"time"

	"golang.org/x/time/rate"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/apiclient"
)

func newCMRateLimiter() workqueue.TypedRateLimiter[any] {
	return workqueue.NewTypedMaxOfRateLimiter(
		workqueue.NewTypedItemExponentialFailureRateLimiter[any](500*time.Millisecond, 10*time.Second),
		// 10 qps, 100 bucket size.
		&workqueue.TypedBucketRateLimiter[any]{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
	)
}

// PersistedRecord is the metadata a Reconcile pass needs from a persisted entry.
type PersistedRecord interface {
	RequestKey() (remotehttp.FetchKey, bool)
	GetName() string
}

// PersistenceController syncs the fetched-results KRT collection into ConfigMaps.
type PersistenceController[T Result, E PersistedRecord] struct {
	apiClient            apiclient.Client
	cmClient             kclient.Client[*corev1.ConfigMap]
	eventQueue           controllers.Queue
	results              krt.Collection[FetchedRecord[T]]
	entries              krt.Collection[E]
	entriesForRequestKey func(remotehttp.FetchKey) []E
	serialize            func(*corev1.ConfigMap, T) error
	nameFunc             func(remotehttp.FetchKey) string
	labelFunc            func() map[string]string
	labelSelector        func() string
	rateLimiter          workqueue.TypedRateLimiter[any]
	deploymentNamespace  string
	controllerName       string
	reconcileCtx         context.Context
	waitForSync          []cache.InformerSynced
	logger               *slog.Logger
}

type PersistenceControllerOptions[T Result, E PersistedRecord] struct {
	ApiClient            apiclient.Client
	DeploymentNamespace  string
	ControllerName       string
	Results              krt.Collection[FetchedRecord[T]]
	Entries              krt.Collection[E]
	EntriesForRequestKey func(remotehttp.FetchKey) []E
	Serialize            func(*corev1.ConfigMap, T) error
	NameFunc             func(remotehttp.FetchKey) string
	LabelFunc            func() map[string]string
	LabelSelector        func() string
	StoreHasSynced       func() bool
	Logger               *slog.Logger
}

func NewPersistenceController[T Result, E PersistedRecord](opts PersistenceControllerOptions[T, E]) *PersistenceController[T, E] {
	return &PersistenceController[T, E]{
		apiClient:            opts.ApiClient,
		deploymentNamespace:  opts.DeploymentNamespace,
		controllerName:       opts.ControllerName,
		results:              opts.Results,
		entries:              opts.Entries,
		entriesForRequestKey: opts.EntriesForRequestKey,
		serialize:            opts.Serialize,
		nameFunc:             opts.NameFunc,
		labelFunc:            opts.LabelFunc,
		labelSelector:        opts.LabelSelector,
		rateLimiter:          newCMRateLimiter(),
		waitForSync:          []cache.InformerSynced{opts.Results.HasSynced, opts.Entries.HasSynced, opts.StoreHasSynced},
		logger:               opts.Logger,
	}
}

func (c *PersistenceController[T, E]) Init(ctx context.Context) {
	c.cmClient = kclient.NewFiltered[*corev1.ConfigMap](c.apiClient,
		kclient.Filter{
			ObjectFilter:  c.apiClient.ObjectFilter(),
			Namespace:     c.deploymentNamespace,
			LabelSelector: c.labelSelector(),
		})

	c.waitForSync = append([]cache.InformerSynced{c.cmClient.HasSynced}, c.waitForSync...)

	c.eventQueue = controllers.NewQueue(
		c.controllerName,
		controllers.WithReconciler(c.Reconcile),
		controllers.WithMaxAttempts(math.MaxInt),
		controllers.WithRateLimiter(c.rateLimiter),
	)
}

func (c *PersistenceController[T, E]) Start(ctx context.Context) error {
	c.reconcileCtx = ctx

	c.logger.Info("waiting for cache to sync")
	c.apiClient.Core().WaitForCacheSync(
		c.controllerName,
		ctx.Done(),
		c.waitForSync...,
	)

	c.logger.Info("starting persistence controller")
	resultRegistration := c.results.RegisterBatch(func(events []krt.Event[FetchedRecord[T]]) {
		for _, event := range events {
			c.enqueueFetchedRecord(event.Old)
			c.enqueueFetchedRecord(event.New)
		}
	}, true)
	defer resultRegistration.UnregisterHandler()

	persistedRegistration := c.entries.RegisterBatch(func(events []krt.Event[E]) {
		for _, event := range events {
			c.enqueuePersistedRecord(event.Old)
			c.enqueuePersistedRecord(event.New)
		}
	}, true)
	defer persistedRegistration.UnregisterHandler()

	go c.eventQueue.Run(ctx.Done())

	if !resultRegistration.WaitUntilSynced(ctx.Done()) {
		return nil
	}
	if !persistedRegistration.WaitUntilSynced(ctx.Done()) {
		return nil
	}

	<-ctx.Done()
	return nil
}

func (c *PersistenceController[T, E]) Reconcile(req types.NamespacedName) error {
	c.logger.Debug("syncing fetched result to ConfigMap(s)")
	ctx := c.reconcileCtx
	requestKey := remotehttp.FetchKey(req.Name)

	existingEntries := c.entriesForRequestKey(requestKey)
	existingNames := make([]string, 0, len(existingEntries))
	for _, entry := range existingEntries {
		existingNames = append(existingNames, entry.GetName())
	}

	result := c.results.GetKey(string(requestKey))
	var record T
	exists := result != nil
	var canonicalName string
	if exists {
		record = result.Payload
		canonicalName = c.nameFunc(requestKey)
	}

	plan := PlanConfigMapSync(existingNames, canonicalName, exists)

	if plan.UpsertName != "" {
		if err := c.upsertConfigMap(ctx, req.Namespace, plan.UpsertName, record); err != nil {
			return err
		}
	}
	for _, deleteName := range plan.DeleteNames {
		c.logger.Debug("deleting ConfigMap", "name", deleteName)
		if err := client.IgnoreNotFound(c.apiClient.Kube().CoreV1().ConfigMaps(req.Namespace).Delete(ctx, deleteName, metav1.DeleteOptions{})); err != nil {
			return err
		}
	}

	return nil
}

func (c *PersistenceController[T, E]) NeedLeaderElection() bool {
	return true
}

func (c *PersistenceController[T, E]) newStoreConfigMap(name string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: c.deploymentNamespace,
			Labels:    c.labelFunc(),
		},
		Data: make(map[string]string),
	}
}

func (c *PersistenceController[T, E]) enqueueFetchedRecord(record *FetchedRecord[T]) {
	if record == nil {
		return
	}
	c.eventQueue.Add(RequestQueueKey(c.deploymentNamespace, record.Payload.RemoteRequestKey()))
}

func (c *PersistenceController[T, E]) enqueuePersistedRecord(entry *E) {
	if entry == nil {
		return
	}
	requestKey, ok := (*entry).RequestKey()
	if !ok {
		return
	}
	c.eventQueue.Add(RequestQueueKey(c.deploymentNamespace, requestKey))
}

func (c *PersistenceController[T, E]) upsertConfigMap(ctx context.Context, namespace, name string, record T) error {
	existingCm := c.cmClient.Get(name, namespace)
	if existingCm == nil {
		c.logger.Debug("creating ConfigMap", "name", name)
		newCm := c.newStoreConfigMap(name)
		if err := c.serialize(newCm, record); err != nil {
			c.logger.Error("error setting record in ConfigMap", "error", err)
			return err
		}

		if _, err := c.apiClient.Kube().CoreV1().ConfigMaps(namespace).Create(ctx, newCm, metav1.CreateOptions{}); err != nil {
			c.logger.Error("error creating ConfigMap", "error", err)
			return err
		}
		return nil
	}

	c.logger.Debug("updating ConfigMap", "name", name)
	if err := c.serialize(existingCm, record); err != nil {
		c.logger.Error("error setting record in ConfigMap", "error", err)
		return err
	}
	if _, err := c.apiClient.Kube().CoreV1().ConfigMaps(namespace).Update(ctx, existingCm, metav1.UpdateOptions{}); err != nil {
		c.logger.Error("error updating ConfigMap", "error", err)
		return err
	}
	return nil
}

type SyncPlan struct {
	UpsertName  string
	DeleteNames []string
}

// PlanConfigMapSync chooses upsert/delete names from existing names and the canonical name.
func PlanConfigMapSync(
	existingNames []string,
	canonicalName string,
	exists bool,
) SyncPlan {
	if exists {
		deleteNames := make([]string, 0, len(existingNames))
		for _, name := range existingNames {
			if name != canonicalName {
				deleteNames = append(deleteNames, name)
			}
		}
		return SyncPlan{
			UpsertName:  canonicalName,
			DeleteNames: deleteNames,
		}
	}

	return SyncPlan{
		DeleteNames: existingNames,
	}
}

func RequestQueueKey(namespace string, requestKey remotehttp.FetchKey) types.NamespacedName {
	return types.NamespacedName{
		Namespace: namespace,
		Name:      string(requestKey),
	}
}
