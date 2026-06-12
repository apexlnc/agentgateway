package remotecache

import (
	"context"
	"fmt"
	"log/slog"

	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

// FetchKeyIndexCollectionOption keys an index collection by FetchKey.
var FetchKeyIndexCollectionOption = krt.WithIndexCollectionFromString(func(s string) remotehttp.FetchKey {
	return remotehttp.FetchKey(s)
})

type StoreOptions[S Request, R Result[R]] struct {
	Fetcher  *Fetcher[S, R]
	Requests krt.Collection[S]
	Logger   *slog.Logger

	// Hydrate, if non-nil, populates Fetcher.Results before request
	// registration. Errors are logged but never block Start so a transient
	// persistence failure cannot stall fresh fetches.
	Hydrate func(ctx context.Context) ([]R, error)
}

// Store bridges KRT-derived shared fetch requests to a runtime Fetcher.
type Store[S Request, R Result[R]] struct {
	Fetcher *Fetcher[S, R]
	opts    StoreOptions[S, R]
	ready   chan struct{}
}

func NewStore[S Request, R Result[R]](opts StoreOptions[S, R]) *Store[S, R] {
	return &Store[S, R]{
		Fetcher: opts.Fetcher,
		opts:    opts,
		ready:   make(chan struct{}),
	}
}

func (s *Store[S, R]) Start(ctx context.Context) error {
	s.opts.Logger.Info("starting remote fetch store")

	if s.opts.Hydrate != nil {
		stored, err := s.opts.Hydrate(ctx)
		if err != nil {
			s.opts.Logger.Error("error hydrating remote results from persistence", "error", err)
		}
		s.opts.Fetcher.Results.Reset(stored)
	}

	registration := s.opts.Requests.Register(func(event krt.Event[S]) {
		switch event.Event {
		case controllers.EventAdd, controllers.EventUpdate:
			if event.New == nil {
				return
			}
			// On request-key change, retire the old key. This stops fetching it
			// but preserves its result so existing traffic can continue using
			// last-known-good data until a newer fetch for the same resource
			// (under a different key) or an orphan sweep removes it.
			if event.Event == controllers.EventUpdate && event.Old != nil {
				oldKey := (*event.Old).RemoteRequestKey()
				newKey := (*event.New).RemoteRequestKey()
				if oldKey != newKey {
					s.opts.Logger.Debug("retiring stale record after request key change", "old_request_key", oldKey, "new_request_key", newKey)
					s.opts.Fetcher.Retire(oldKey)
				}
			}

			s.opts.Fetcher.AddOrUpdate(*event.New)
		case controllers.EventDelete:
			if event.Old == nil {
				return
			}
			s.opts.Fetcher.Remove((*event.Old).RemoteRequestKey())
		}
	})
	defer registration.UnregisterHandler()

	go s.opts.Fetcher.Run(ctx)

	if !registration.WaitUntilSynced(ctx.Done()) {
		// WaitUntilSynced returns false either because ctx was cancelled
		// (graceful shutdown — surface ctx.Err() so the supervisor sees the
		// real cause) or because sync failed for non-context reasons. In the
		// latter case return an explicit error so the supervisor doesn't mark
		// this Runnable healthy.
		if err := ctx.Err(); err != nil {
			return err
		}
		return fmt.Errorf("remote fetch store: request collection did not sync")
	}

	s.opts.Fetcher.SweepOrphans()

	close(s.ready)
	<-ctx.Done()
	return nil
}

func (s *Store[S, R]) HasSynced() bool {
	select {
	case <-s.ready:
		return true
	default:
		return false
	}
}

func (s *Store[S, R]) NeedLeaderElection() bool {
	return true
}
