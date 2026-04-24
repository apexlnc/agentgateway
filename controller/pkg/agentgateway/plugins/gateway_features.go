package plugins

import (
	"sigs.k8s.io/gateway-api/pkg/features"
)

const SupportOIDC features.FeatureName = "OIDC"

var OIDCFeature = features.Feature{
	Name:    SupportOIDC,
	Channel: features.FeatureChannelExperimental,
}

func init() {
	features.AllFeatures.Insert(OIDCFeature)
}
