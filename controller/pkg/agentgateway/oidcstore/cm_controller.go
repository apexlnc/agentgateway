package agentoidcstore

import (
	"context"
	"math"
	"time"

	"golang.org/x/time/rate"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/kclient"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/apiclient"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
)

var cmLogger = logging.New("oidc_store_config_map_controller")

var cmRateLimiter = workqueue.NewTypedMaxOfRateLimiter(
	workqueue.NewTypedItemExponentialFailureRateLimiter[any](500*time.Millisecond, 10*time.Second),
	&workqueue.TypedBucketRateLimiter[any]{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
)

type ConfigMapsController struct {
	apiClient           apiclient.Client
	cmClient            kclient.Client[*corev1.ConfigMap]
	eventQueue          controllers.Queue
	providerUpdates     chan map[remotehttp.FetchKey]struct{}
	store               *oidc.OIDCStore
	deploymentNamespace string
	storePrefix         string
	waitForSync         []cache.InformerSynced
}

func NewConfigMapsController(apiClient apiclient.Client, storePrefix, deploymentNamespace string, store *oidc.OIDCStore) *ConfigMapsController {
	return &ConfigMapsController{
		apiClient:           apiClient,
		deploymentNamespace: deploymentNamespace,
		storePrefix:         storePrefix,
		store:               store,
	}
}

func (c *ConfigMapsController) Init(ctx context.Context) {
	c.cmClient = kclient.NewFiltered[*corev1.ConfigMap](c.apiClient,
		kclient.Filter{
			ObjectFilter:  c.apiClient.ObjectFilter(),
			Namespace:     c.deploymentNamespace,
			LabelSelector: oidc.ProviderStoreLabelSelector(c.storePrefix),
		},
	)
	c.waitForSync = []cache.InformerSynced{c.cmClient.HasSynced}
	c.providerUpdates = c.store.SubscribeToProviderUpdates()
	c.eventQueue = controllers.NewQueue("OidcStoreConfigMapController", controllers.WithReconciler(c.Reconcile), controllers.WithMaxAttempts(math.MaxInt), controllers.WithRateLimiter(cmRateLimiter))
}

func (c *ConfigMapsController) Start(ctx context.Context) error {
	cmLogger.Info("waiting for cache to sync")
	c.apiClient.Core().WaitForCacheSync("kube oidc store ConfigMap syncer", ctx.Done(), c.waitForSync...)

	go func() {
		for {
			select {
			case updates := <-c.providerUpdates:
				for key := range updates {
					c.eventQueue.AddObject(c.newProviderConfigMap(oidc.ProviderConfigMapName(c.storePrefix, key)))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	if !c.store.WaitForSourceSync(ctx) {
		return nil
	}

	c.cmClient.AddEventHandler(controllers.FromEventHandler(func(o controllers.Event) {
		c.eventQueue.AddObject(o.Latest())
	}))
	for _, cm := range c.cmClient.List(c.deploymentNamespace, labels.Everything()) {
		c.eventQueue.AddObject(cm)
	}
	go c.eventQueue.Run(ctx.Done())

	<-ctx.Done()
	return nil
}

func (c *ConfigMapsController) Reconcile(req types.NamespacedName) error {
	ctx := context.Background()
	_, cfg, ok := c.store.ProviderByConfigMapName(req.Name)
	if !ok {
		return client.IgnoreNotFound(c.apiClient.Kube().CoreV1().ConfigMaps(req.Namespace).Delete(ctx, req.Name, metav1.DeleteOptions{}))
	}

	existing := c.cmClient.Get(req.Name, req.Namespace)
	if existing == nil {
		newCM := c.newProviderConfigMap(req.Name)
		if err := oidc.SetProviderConfigInConfigMap(newCM, cfg); err != nil {
			return err
		}
		_, err := c.apiClient.Kube().CoreV1().ConfigMaps(req.Namespace).Create(ctx, newCM, metav1.CreateOptions{})
		return err
	}

	if err := oidc.SetProviderConfigInConfigMap(existing, cfg); err != nil {
		return err
	}
	_, err := c.apiClient.Kube().CoreV1().ConfigMaps(req.Namespace).Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

func (c *ConfigMapsController) NeedLeaderElection() bool {
	return true
}

func (c *ConfigMapsController) newProviderConfigMap(name string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: c.deploymentNamespace,
			Labels:    oidc.ProviderStoreConfigMapLabel(c.storePrefix),
		},
		Data: map[string]string{},
	}
}
