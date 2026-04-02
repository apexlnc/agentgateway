package jwks_url

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"istio.io/istio/pkg/kube/krt"
	corev1 "k8s.io/api/core/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

type JwksUrlBuilder interface {
	BuildJwksUrlAndTlsConfig(krtctx krt.HandlerContext, policyName, defaultNS string, remoteProvider *agentgateway.RemoteJWKS) (string, *tls.Config, error)
}

var JwksUrlBuilderFactory = func() JwksUrlBuilder { return &emptyJwksUrlFactory{} }

type emptyJwksUrlFactory struct{}

func (f *emptyJwksUrlFactory) BuildJwksUrlAndTlsConfig(_ krt.HandlerContext, _, _ string, _ *agentgateway.RemoteJWKS) (string, *tls.Config, error) {
	return "", nil, fmt.Errorf("JwksUrlBuilderFactory must be initialized before use")
}

type defaultJwksUrlFactory struct {
	resolver *remotehttp.Resolver
}

func NewJwksUrlFactory(cfgmaps krt.Collection[*corev1.ConfigMap],
	backends krt.Collection[*agentgateway.AgentgatewayBackend],
	agentgatewayPolicies krt.Collection[*agentgateway.AgentgatewayPolicy]) JwksUrlBuilder {
	return NewJwksUrlFactoryFromResolver(remotehttp.NewResolver(cfgmaps, backends, agentgatewayPolicies))
}

func NewJwksUrlFactoryFromResolver(resolver *remotehttp.Resolver) JwksUrlBuilder {
	return &defaultJwksUrlFactory{resolver: resolver}
}

func (f *defaultJwksUrlFactory) BuildJwksUrlAndTlsConfig(krtctx krt.HandlerContext, policyName, defaultNS string, remoteProvider *agentgateway.RemoteJWKS) (string, *tls.Config, error) {
	resolved, err := f.resolver.Resolve(krtctx, policyName, defaultNS, remoteProvider.BackendRef, remoteProvider.JwksPath, "")
	if err != nil {
		return "", nil, err
	}
	return resolved.Target.URL, resolved.TLSConfig, nil
}

func GetTLSConfig(
	krtctx krt.HandlerContext,
	cfgmaps krt.Collection[*corev1.ConfigMap],
	namespace string,
	btls *agentgateway.BackendTLS,
) (*tls.Config, error) {
	tlsConfig, _, err := remotehttp.GetTLSConfig(krtctx, cfgmaps, namespace, btls)
	return tlsConfig, err
}

func AppendPoolWithCertsFromConfigMap(pool *x509.CertPool, cm *corev1.ConfigMap) bool {
	return remotehttp.AppendPoolWithCertsFromConfigMap(pool, cm)
}
