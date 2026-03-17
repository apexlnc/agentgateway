package jwks

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// jwksCache stores fetched JWKS keysets by request key.
type jwksCache struct {
	l       sync.Mutex
	keysets map[RequestKey]Keyset
}

func newCache() *jwksCache {
	return &jwksCache{
		keysets: make(map[RequestKey]Keyset),
	}
}

func (c *jwksCache) LoadJwksFromStores(stored []Keyset) error {
	newCache := newCache()
	errs := make([]error, 0)

	for _, keyset := range stored {
		jwks := jose.JSONWebKeySet{}
		if err := json.Unmarshal([]byte(keyset.JwksJSON), &jwks); err != nil {
			errs = append(errs, err)
			continue
		}

		newCache.keysets[keyset.RequestKey] = keyset
	}

	c.l.Lock()
	c.keysets = newCache.keysets
	c.l.Unlock()
	return errors.Join(errs...)
}

func (c *jwksCache) GetJwks(requestKey RequestKey) (Keyset, bool) {
	c.l.Lock()
	defer c.l.Unlock()

	keyset, ok := c.keysets[requestKey]
	return keyset, ok
}

func (c *jwksCache) addJwks(requestKey RequestKey, requestURL string, jwks jose.JSONWebKeySet) error {
	serializedJwks, err := json.Marshal(jwks)
	if err != nil {
		return err
	}

	c.l.Lock()
	defer c.l.Unlock()

	keyset := Keyset{
		RequestKey: requestKey,
		URL:        requestURL,
		FetchedAt:  time.Now(),
		JwksJSON:   string(serializedJwks),
	}
	c.keysets[requestKey] = keyset
	return nil
}

func (c *jwksCache) deleteJwks(requestKey RequestKey) {
	c.l.Lock()
	delete(c.keysets, requestKey)
	c.l.Unlock()
}
