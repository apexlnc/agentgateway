package remotehttp

import (
	"crypto/md5" //nolint:gosec
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	krtpkg "github.com/agentgateway/agentgateway/controller/pkg/utils/krtutil"
	"github.com/agentgateway/agentgateway/controller/pkg/utils/kubeutils"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

type FetchKey string

type FetchTarget struct {
	URL string
}

type ResolvedTarget struct {
	RequestKey FetchKey
	Target     FetchTarget
	TLSConfig  *tls.Config
}

type tlsKeyMaterial struct {
	ServerName         string   `json:"serverName,omitempty"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify,omitempty"`
	NextProtos         []string `json:"nextProtos,omitempty"`
	CACertificates     []string `json:"caCertificates,omitempty"`
}

type TargetRefIndexKey struct {
	Group     string
	Kind      string
	Name      string
	Namespace string
}

func (k TargetRefIndexKey) String() string {
	return fmt.Sprintf("%s:%s:%s:%s", k.Group, k.Kind, k.Namespace, k.Name)
}

type Resolver struct {
	cfgmaps                  krt.Collection[*corev1.ConfigMap]
	policiesByTargetRefIndex krt.Index[TargetRefIndexKey, *agentgateway.AgentgatewayPolicy]
	backends                 krt.Collection[*agentgateway.AgentgatewayBackend]
	agentgatewayPolicies     krt.Collection[*agentgateway.AgentgatewayPolicy]
}

func NewResolver(
	cfgmaps krt.Collection[*corev1.ConfigMap],
	backends krt.Collection[*agentgateway.AgentgatewayBackend],
	agentgatewayPolicies krt.Collection[*agentgateway.AgentgatewayPolicy],
) *Resolver {
	policiesByTargetRefIndex := krtpkg.UnnamedIndex(agentgatewayPolicies, func(in *agentgateway.AgentgatewayPolicy) []TargetRefIndexKey {
		keys := make([]TargetRefIndexKey, 0, len(in.Spec.TargetRefs))
		for _, ref := range in.Spec.TargetRefs {
			keys = append(keys, TargetRefIndexKey{
				Name:      string(ref.Name),
				Kind:      string(ref.Kind),
				Group:     string(ref.Group),
				Namespace: in.Namespace,
			})
		}
		return keys
	})

	return &Resolver{
		cfgmaps:                  cfgmaps,
		policiesByTargetRefIndex: policiesByTargetRefIndex,
		backends:                 backends,
		agentgatewayPolicies:     agentgatewayPolicies,
	}
}

func (r *Resolver) Resolve(
	krtctx krt.HandlerContext,
	ownerName, defaultNS string,
	ref gwv1.BackendObjectReference,
	path string,
	issuer string,
) (*ResolvedTarget, error) {
	refName := string(ref.Name)
	refNamespace := string(ptr.OrDefault(ref.Namespace, gwv1.Namespace(defaultNS)))
	cleanPath := strings.TrimPrefix(path, "/")

	switch string(*ref.Kind) {
	case wellknown.AgentgatewayBackendGVK.Kind:
		backendRef := types.NamespacedName{Name: refName, Namespace: refNamespace}
		backend := ptr.Flatten(krt.FetchOne(krtctx, r.backends, krt.FilterObjectName(backendRef)))
		if backend == nil {
			return nil, fmt.Errorf("backend %s not found, policy %s", backendRef, types.NamespacedName{Namespace: defaultNS, Name: ownerName})
		}
		if backend.Spec.Static == nil {
			return nil, fmt.Errorf("only static backends are supported; backend: %s, policy: %s", backendRef, types.NamespacedName{Namespace: defaultNS, Name: ownerName})
		}

		tlsConfig, material, err := r.resolveBackendTLS(krtctx, refNamespace, ref, ownerName, backend.Spec.Policies)
		if err != nil {
			return nil, err
		}

		url := fmt.Sprintf("http://%s:%d/%s", backend.Spec.Static.Host, backend.Spec.Static.Port, cleanPath)
		if tlsConfig != nil {
			url = fmt.Sprintf("https://%s:%d/%s", backend.Spec.Static.Host, backend.Spec.Static.Port, cleanPath)
		}

		return &ResolvedTarget{
			RequestKey: BuildFetchKey(url, issuer, material),
			Target:     FetchTarget{URL: url},
			TLSConfig:  tlsConfig,
		}, nil
	case wellknown.ServiceKind:
		tlsConfig, material, err := r.resolveServiceTLS(krtctx, refNamespace, ref, ownerName)
		if err != nil {
			return nil, err
		}

		host := kubeutils.GetServiceHostname(refName, refNamespace)
		fqdn := host
		if port := ptr.OrEmpty(ref.Port); port != 0 {
			fqdn = fmt.Sprintf("%s:%d", host, port)
		}

		url := fmt.Sprintf("http://%s/%s", fqdn, cleanPath)
		if tlsConfig != nil {
			url = fmt.Sprintf("https://%s/%s", fqdn, cleanPath)
		}

		return &ResolvedTarget{
			RequestKey: BuildFetchKey(url, issuer, material),
			Target:     FetchTarget{URL: url},
			TLSConfig:  tlsConfig,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported target kind in remote fetch provider; kind: %s, policy: %s", string(*ref.Kind), types.NamespacedName{Namespace: refNamespace, Name: ownerName})
	}
}

func BuildFetchKey(url, issuer string, material *tlsKeyMaterial) FetchKey {
	payload := struct {
		URL    string          `json:"url"`
		Issuer string          `json:"issuer,omitempty"`
		TLS    *tlsKeyMaterial `json:"tls,omitempty"`
	}{
		URL:    url,
		Issuer: issuer,
		TLS:    material,
	}
	raw, _ := json.Marshal(payload)
	sum := md5.Sum(raw) //nolint:gosec
	return FetchKey(hex.EncodeToString(sum[:]))
}

func (r *Resolver) resolveBackendTLS(
	krtctx krt.HandlerContext,
	namespace string,
	ref gwv1.BackendObjectReference,
	ownerName string,
	policies *agentgateway.BackendFull,
) (*tls.Config, *tlsKeyMaterial, error) {
	if policies != nil && policies.TLS != nil {
		tlsc, material, err := GetTLSConfig(krtctx, r.cfgmaps, namespace, policies.TLS)
		if err != nil {
			return nil, nil, fmt.Errorf("error setting tls options; backend: %s/%s, policy: %s, %w", namespace, ref.Name, types.NamespacedName{Namespace: namespace, Name: ownerName}, err)
		}
		return tlsc, material, nil
	}

	agwPolicy := ptr.Flatten(krt.FetchOne(krtctx, r.agentgatewayPolicies, krt.FilterIndex(r.policiesByTargetRefIndex, TargetRefIndexKey{
		Name:      string(ref.Name),
		Kind:      string(ptr.OrEmpty(ref.Kind)),
		Group:     string(ptr.OrEmpty(ref.Group)),
		Namespace: namespace,
	})))
	if agwPolicy == nil || agwPolicy.Spec.Backend == nil || agwPolicy.Spec.Backend.TLS == nil {
		return nil, nil, nil
	}

	tlsc, material, err := GetTLSConfig(krtctx, r.cfgmaps, namespace, agwPolicy.Spec.Backend.TLS)
	if err != nil {
		return nil, nil, fmt.Errorf("error setting tls options; backend: %s/%s, policy: %s, %w", namespace, ref.Name, types.NamespacedName{Namespace: namespace, Name: ownerName}, err)
	}
	return tlsc, material, nil
}

func (r *Resolver) resolveServiceTLS(
	krtctx krt.HandlerContext,
	namespace string,
	ref gwv1.BackendObjectReference,
	ownerName string,
) (*tls.Config, *tlsKeyMaterial, error) {
	agwPolicy := ptr.Flatten(krt.FetchOne(krtctx, r.agentgatewayPolicies, krt.FilterIndex(r.policiesByTargetRefIndex, TargetRefIndexKey{
		Name:      string(ref.Name),
		Kind:      string(ptr.OrEmpty(ref.Kind)),
		Group:     string(ptr.OrEmpty(ref.Group)),
		Namespace: namespace,
	})))
	if agwPolicy == nil || agwPolicy.Spec.Backend == nil || agwPolicy.Spec.Backend.TLS == nil {
		return nil, nil, nil
	}

	tlsc, material, err := GetTLSConfig(krtctx, r.cfgmaps, namespace, agwPolicy.Spec.Backend.TLS)
	if err != nil {
		return nil, nil, fmt.Errorf("error setting tls options; service %s/%s, policy: %s %w", ref.Name, namespace, types.NamespacedName{Namespace: namespace, Name: ownerName}, err)
	}
	return tlsc, material, nil
}

func GetTLSConfig(
	krtctx krt.HandlerContext,
	cfgmaps krt.Collection[*corev1.ConfigMap],
	namespace string,
	btls *agentgateway.BackendTLS,
) (*tls.Config, *tlsKeyMaterial, error) {
	material := &tlsKeyMaterial{
		ServerName:         ptr.OrEmpty(btls.Sni),
		InsecureSkipVerify: insecureSkipVerify(btls.InsecureSkipVerify),
		NextProtos:         ptr.OrEmpty(btls.AlpnProtocols),
	}
	toret := tls.Config{
		ServerName:         material.ServerName,
		InsecureSkipVerify: material.InsecureSkipVerify, //nolint:gosec
		NextProtos:         material.NextProtos,
	}

	if len(btls.CACertificateRefs) > 0 {
		certPool := x509.NewCertPool()
		for _, ref := range btls.CACertificateRefs {
			nn := types.NamespacedName{Name: ref.Name, Namespace: namespace}
			cfgmap := krt.FetchOne(krtctx, cfgmaps, krt.FilterObjectName(nn))
			if cfgmap == nil {
				return nil, nil, fmt.Errorf("ConfigMap %s not found", nn)
			}
			cm := ptr.Flatten(cfgmap)
			caCrt, ok := cm.Data["ca.crt"]
			if !ok || !certPool.AppendCertsFromPEM([]byte(caCrt)) {
				return nil, nil, fmt.Errorf("error extracting CA cert from ConfigMap %s", nn)
			}
			material.CACertificates = append(material.CACertificates, caCrt)
		}
		toret.RootCAs = certPool
	}

	return &toret, material, nil
}

func AppendPoolWithCertsFromConfigMap(pool *x509.CertPool, cm *corev1.ConfigMap) bool {
	caCrts, ok := cm.Data["ca.crt"]
	if !ok {
		return false
	}
	return pool.AppendCertsFromPEM([]byte(caCrts))
}

func insecureSkipVerify(mode *agentgateway.InsecureTLSMode) bool {
	return mode != nil
}
