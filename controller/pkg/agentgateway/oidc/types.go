package oidc

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

const (
	DefaultProviderStorePrefix = "oidc-provider"
	DefaultDiscoveryPath       = "/.well-known/openid-configuration"
	RunnableName               = "oidc-store"
	ProviderConfigMapKey       = "provider.json"
	componentLabel             = "app.kubernetes.io/component"
)

type OwnerKey string

func (o OwnerKey) String() string {
	return string(o)
}

type ProviderSource struct {
	OwnerKey   OwnerKey
	Issuer     string
	RequestKey remotehttp.FetchKey
	Target     remotehttp.FetchTarget
	TLSConfig  *tls.Config
	TTL        time.Duration
	Deleted    bool
}

func (s ProviderSource) ResourceName() string {
	return string(s.RequestKey)
}

func (s ProviderSource) Equals(other ProviderSource) bool {
	return s.OwnerKey == other.OwnerKey &&
		s.Issuer == other.Issuer &&
		s.RequestKey == other.RequestKey &&
		s.Target == other.Target &&
		s.TTL == other.TTL &&
		s.Deleted == other.Deleted &&
		reflect.DeepEqual(s.TLSConfig, other.TLSConfig)
}

type ProviderConfig struct {
	RequestKey            remotehttp.FetchKey `json:"requestKey"`
	DiscoveryURL          string              `json:"discoveryUrl"`
	FetchedAt             time.Time           `json:"fetchedAt"`
	Issuer                string              `json:"issuer"`
	AuthorizationEndpoint string              `json:"authorizationEndpoint"`
	TokenEndpoint         string              `json:"tokenEndpoint"`
	TokenEndpointAuth     string              `json:"tokenEndpointAuth"`
	JwksURI               string              `json:"jwksUri"`
	JwksInline            string              `json:"jwksInline"`
}

func (c ProviderConfig) Validate() error {
	if c.RequestKey == "" {
		return fmt.Errorf("provider config requestKey is required")
	}
	if c.DiscoveryURL == "" {
		return fmt.Errorf("provider config discoveryUrl is required")
	}
	if c.Issuer == "" {
		return fmt.Errorf("provider config issuer is required")
	}
	if c.AuthorizationEndpoint == "" {
		return fmt.Errorf("provider config authorizationEndpoint is required")
	}
	if c.TokenEndpoint == "" {
		return fmt.Errorf("provider config tokenEndpoint is required")
	}
	if c.TokenEndpointAuth == "" {
		return fmt.Errorf("provider config tokenEndpointAuth is required")
	}
	if c.JwksURI == "" {
		return fmt.Errorf("provider config jwksUri is required")
	}
	if !json.Valid([]byte(c.JwksInline)) {
		return fmt.Errorf("provider config jwksInline must contain valid JSON")
	}
	return nil
}

func ProviderStoreLabelSelector(storePrefix string) string {
	return componentLabel + "=" + storePrefix
}

func ProviderStoreConfigMapLabel(storePrefix string) map[string]string {
	return map[string]string{componentLabel: storePrefix}
}

func ProviderConfigMapName(storePrefix string, requestKey remotehttp.FetchKey) string {
	return fmt.Sprintf("%s-%s", storePrefix, requestKey)
}

func ProviderConfigMapNamespacedName(namespace, storePrefix string, requestKey remotehttp.FetchKey) types.NamespacedName {
	return types.NamespacedName{
		Namespace: namespace,
		Name:      ProviderConfigMapName(storePrefix, requestKey),
	}
}

func PolicyOwnerKey(namespace, name, path string) OwnerKey {
	return OwnerKey(strings.Join([]string{"policy", namespace, name, path}, "/"))
}
