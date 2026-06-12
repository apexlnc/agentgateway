package remotehttp

import "crypto/tls"

type FetchTarget struct {
	URL            string               `json:"url"`
	Transport      TransportFingerprint `json:"transport"`
	ProxyURL       string               `json:"proxyURL,omitempty"`
	ProxyTransport TransportFingerprint `json:"proxyTransport"`
}

// Equals avoids reflect.DeepEqual on the KRT diff hot path.
func (t FetchTarget) Equals(other FetchTarget) bool {
	return t.URL == other.URL &&
		t.ProxyURL == other.ProxyURL &&
		t.Transport.Equals(other.Transport) &&
		t.ProxyTransport.Equals(other.ProxyTransport)
}

type ResolvedTarget struct {
	Key            FetchKey
	Target         FetchTarget
	TLSConfig      *tls.Config
	ProxyTLSConfig *tls.Config
}
