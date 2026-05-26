package remotehttp

import (
	"slices"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
)

type TransportFingerprint struct {
	// Zero value means strict/default verification.
	Verification agentgateway.InsecureTLSMode `json:"verification,omitempty"`
	ServerName   string                       `json:"serverName,omitempty"`
	CABundleHash string                       `json:"caBundleHash,omitempty"`
	NextProtos   []string                     `json:"nextProtos,omitempty"`
}

// Equals avoids reflect.DeepEqual on the KRT diff hot path.
func (t TransportFingerprint) Equals(other TransportFingerprint) bool {
	return t.Verification == other.Verification &&
		t.ServerName == other.ServerName &&
		t.CABundleHash == other.CABundleHash &&
		slices.Equal(t.NextProtos, other.NextProtos)
}
