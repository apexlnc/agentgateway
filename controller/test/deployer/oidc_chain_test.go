package deployer

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/agentgateway/agentgateway/controller/pkg/apiclient/fake"
	pkgdeployer "github.com/agentgateway/agentgateway/controller/pkg/deployer"
	"github.com/agentgateway/agentgateway/controller/pkg/schemes"
	"github.com/agentgateway/agentgateway/controller/pkg/utils/fsutils"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

func TestOIDCRawConfigChainIsDeterministic(t *testing.T) {
	mockVersion(t)

	tester := DeployerTester{
		AgwControllerName: wellknown.DefaultAgwControllerName,
		AgwClassName:      wellknown.DefaultAgwClassName,
	}
	testCase := HelmTestCase{InputFile: "agentgateway-rawconfig-oidc"}
	dir := fsutils.MustGetThisDir()
	scheme := schemes.GatewayScheme()
	objs := tester.GetObjects(t, testCase, scheme, dir)
	fakeClient := fake.NewClient(t, objs...)
	agwCols := NewAgwCols(t)
	inputs := DefaultDeployerInputs(tester, agwCols)
	gwParams := pkgdeployer.NewGatewayParameters(fakeClient, inputs)
	gwParams.WithSessionKeyGenerator(func() (string, error) { return testSessionKey, nil })
	gwParams.WithOIDCCookieSecretGenerator(func() (string, error) { return testSessionKey, nil })

	deployer, err := pkgdeployer.NewGatewayDeployer(
		tester.AgwControllerName,
		tester.AgwClassName,
		scheme,
		fakeClient,
		gwParams,
	)
	require.NoError(t, err)

	_, gateway := ExtractCommonObjs(t, objs)
	require.NotNil(t, gateway)

	ctx := context.Background()
	fakeClient.RunAndWait(ctx.Done())

	first, err := deployer.GetObjsToDeploy(ctx, gateway)
	require.NoError(t, err)
	second, err := deployer.GetObjsToDeploy(ctx, gateway)
	require.NoError(t, err)

	firstYAML, err := objectsToYAML(first)
	require.NoError(t, err)
	secondYAML, err := objectsToYAML(second)
	require.NoError(t, err)
	assert.Equal(t, string(firstYAML), string(secondYAML), "reconcile output should be stable across repeated renders")

	deployment := mustFindDeployment(t, first)
	secret := mustFindSecret(t, first, "gw-oidc-cookie-secret")
	assert.Equal(t, testSessionKey, string(secret.Data["key"]))
	require.NotNil(t, deployment.Spec.Template.Annotations)
	assert.Equal(t,
		"2a8abfa8cb9906290437854193ca6bca41d4d4e26d1d454bd66a35158095e737",
		deployment.Spec.Template.Annotations["checksum/oidc-cookie-secret"],
	)

	env := findEnvVar(t, deployment.Spec.Template.Spec.Containers[0].Env, "OIDC_COOKIE_SECRET")
	require.NotNil(t, env.ValueFrom)
	require.NotNil(t, env.ValueFrom.SecretKeyRef)
	assert.Equal(t, "gw-oidc-cookie-secret", env.ValueFrom.SecretKeyRef.Name)
	assert.Equal(t, "key", env.ValueFrom.SecretKeyRef.Key)

	goldenFile := filepath.Join(dir, "testdata", "agentgateway-rawconfig-oidc-out.yaml")
	assert.FileExists(t, goldenFile)
}

func mustFindDeployment(t *testing.T, objs []client.Object) *appsv1.Deployment {
	t.Helper()
	for _, obj := range objs {
		deployment, ok := obj.(*appsv1.Deployment)
		if ok {
			return deployment
		}
	}
	t.Fatal("expected rendered deployment")
	return nil
}

func mustFindSecret(t *testing.T, objs []client.Object, name string) *corev1.Secret {
	t.Helper()
	for _, obj := range objs {
		secret, ok := obj.(*corev1.Secret)
		if ok && secret.Name == name {
			return secret
		}
	}
	t.Fatalf("expected rendered secret %q", name)
	return nil
}

func findEnvVar(t *testing.T, envs []corev1.EnvVar, name string) corev1.EnvVar {
	t.Helper()
	for _, env := range envs {
		if env.Name == name {
			return env
		}
	}
	t.Fatalf("expected environment variable %q", name)
	return corev1.EnvVar{}
}
