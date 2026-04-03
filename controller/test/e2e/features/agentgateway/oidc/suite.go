//go:build e2e

package oidc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/stretchr/testify/suite"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/test/util/retry"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	agentoidc "github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/utils/fsutils"
	"github.com/agentgateway/agentgateway/controller/test/e2e"
	"github.com/agentgateway/agentgateway/controller/test/e2e/common"
	"github.com/agentgateway/agentgateway/controller/test/e2e/tests/base"
)

var _ e2e.NewSuiteFunc = NewTestingSuite

const (
	namespace       = "agentgateway-base"
	systemNamespace = "agentgateway-system"
	issuer          = "https://agentgateway.dev"
	routeHost       = "oidcroute.com"
	gatewayHost     = "oidcgateway.com"
	clientID        = "mcp_gi3APARn2_uHv2oxfJJqq2yZBDV4OyNo"
)

var (
	setup = base.TestCase{
		Manifests: []string{
			getTestFile("common.yaml"),
		},
	}

	testCases = map[string]*base.TestCase{
		"TestRoutePolicyBackend": {
			Manifests: []string{secureRoutePolicyManifestBackend},
		},
		"TestGatewayPolicyBackend": {
			Manifests: []string{secureGatewayPolicyManifestBackend},
		},
	}
)

type testingSuite struct {
	*base.BaseTestingSuite
}

func NewTestingSuite(ctx context.Context, testInst *e2e.TestInstallation) suite.TestingSuite {
	return &testingSuite{
		BaseTestingSuite: base.NewBaseTestingSuite(ctx, testInst, setup, testCases),
	}
}

var (
	secureRoutePolicyManifestBackend   = getTestFile("secured-route-with-backend.yaml")
	secureGatewayPolicyManifestBackend = getTestFile("secured-gateway-policy-with-backend.yaml")
)

func (s *testingSuite) TestRoutePolicyBackend() {
	s.assertOIDCFlow("route-oidc", "route-policy", routeHost)
}

func (s *testingSuite) TestGatewayPolicyBackend() {
	s.assertOIDCFlow("route-oidc-gw", "gw-policy", gatewayHost)
}

func (s *testingSuite) assertOIDCFlow(routeName, policyName, host string) {
	s.TestInstallation.AssertionsT(s.T()).EventuallyHTTPRouteCondition(
		s.Ctx,
		routeName,
		namespace,
		gwv1.RouteConditionAccepted,
		metav1.ConditionTrue,
	)
	s.TestInstallation.AssertionsT(s.T()).EventuallyAgwPolicyCondition(
		s.Ctx,
		policyName,
		namespace,
		"Accepted",
		metav1.ConditionTrue,
	)
	s.TestInstallation.AssertionsT(s.T()).EventuallyAgwPolicyCondition(
		s.Ctx,
		policyName,
		namespace,
		"Attached",
		metav1.ConditionTrue,
	)

	s.eventuallyAssertProviderConfigCached()

	originalPath := "/private?source=oidc-e2e"
	login := s.eventuallySendGatewayRequest(host, originalPath)
	defer login.Body.Close()

	assert.Equal(s.T(), http.StatusFound, login.StatusCode)
	loginLocation := login.Header.Get("Location")
	assert.Equal(s.T(), true, loginLocation != "")

	loginURL, err := url.Parse(loginLocation)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "/authorize", loginURL.Path)
	assert.Equal(s.T(), "dummy-idp.default:8081", loginURL.Host)
	assert.Equal(s.T(), "http", loginURL.Scheme)
	assert.Equal(s.T(), clientID, loginURL.Query().Get("client_id"))
	assert.Equal(s.T(), true, strings.Contains(loginURL.Query().Get("scope"), "openid"))

	state := loginURL.Query().Get("state")
	nonce := loginURL.Query().Get("nonce")
	assert.Equal(s.T(), true, state != "")
	assert.Equal(s.T(), true, nonce != "")

	redirectURI, err := url.Parse(loginURL.Query().Get("redirect_uri"))
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "/oauth/callback", redirectURI.Path)

	transactionCookie := findCookieByPrefix(login.Cookies(), "agw_oidc_t_")
	if transactionCookie == nil {
		s.T().Fatal("expected transaction cookie")
	}

	callbackPath := fmt.Sprintf(
		"%s?code=%s&state=%s",
		redirectURI.Path,
		url.QueryEscape(authorizationCodeForNonce(nonce)),
		url.QueryEscape(state),
	)
	callback := s.sendGatewayRequest(host, callbackPath, transactionCookie)
	defer callback.Body.Close()

	assert.NoError(s.T(), err)
	assert.Equal(s.T(), http.StatusFound, callback.StatusCode)
	assert.Equal(s.T(), originalPath, callback.Header.Get("Location"))

	sessionCookie := findCookieByPrefix(callback.Cookies(), "agw_oidc_s_")
	if sessionCookie == nil {
		s.T().Fatal("expected session cookie")
	}
	assert.Equal(s.T(), true, hasClearedCookie(callback.Header.Values("Set-Cookie"), transactionCookie.Name))

	final := s.sendGatewayRequest(host, originalPath, sessionCookie)
	defer final.Body.Close()

	assert.Equal(s.T(), http.StatusOK, final.StatusCode)
}

func (s *testingSuite) eventuallyAssertProviderConfigCached() {
	retry.UntilSuccessOrFail(s.T(), func() error {
		var cms corev1.ConfigMapList
		if err := s.TestInstallation.ClusterContext.Client.List(
			s.Ctx,
			&cms,
			ctrlclient.InNamespace(systemNamespace),
			ctrlclient.MatchingLabels(agentoidc.ProviderStoreConfigMapLabel(agentoidc.DefaultProviderStorePrefix)),
		); err != nil {
			return err
		}
		for i := range cms.Items {
			cfg, err := agentoidc.ProviderConfigFromConfigMap(&cms.Items[i])
			if err != nil {
				continue
			}
			if cfg.Issuer == issuer && cfg.AuthorizationEndpoint != "" && cfg.TokenEndpoint != "" && cfg.JwksInline != "" {
				return nil
			}
		}
		return fmt.Errorf("no matching oidc provider ConfigMap cached yet")
	}, retry.Timeout(30*time.Second))
}

func (s *testingSuite) eventuallySendGatewayRequest(hostHeader, requestURI string) *http.Response {
	var response *http.Response
	retry.UntilSuccessOrFail(s.T(), func() error {
		resp := s.sendGatewayRequest(hostHeader, requestURI)
		if resp.StatusCode != http.StatusFound {
			resp.Body.Close()
			return fmt.Errorf("expected 302, got %d", resp.StatusCode)
		}
		if findCookieByPrefix(resp.Cookies(), "agw_oidc_t_") == nil {
			resp.Body.Close()
			return fmt.Errorf("missing oidc transaction cookie")
		}
		response = resp
		return nil
	}, retry.Timeout(30*time.Second))
	return response
}

func (s *testingSuite) sendGatewayRequest(hostHeader, requestURI string, cookies ...*http.Cookie) *http.Response {
	addr := common.BaseGateway.ResolvedAddress()
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "80")
	}

	req, err := http.NewRequestWithContext(s.Ctx, http.MethodGet, "http://"+addr+requestURI, nil)
	assert.NoError(s.T(), err)
	req.Host = hostHeader
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	assert.NoError(s.T(), err)
	return resp
}

func findCookieByPrefix(cookies []*http.Cookie, prefix string) *http.Cookie {
	for _, cookie := range cookies {
		if strings.HasPrefix(cookie.Name, prefix) {
			return cookie
		}
	}
	return nil
}

func hasClearedCookie(setCookies []string, cookieName string) bool {
	for _, value := range setCookies {
		if strings.HasPrefix(value, cookieName+"=") && strings.Contains(value, "Max-Age=0") {
			return true
		}
	}
	return false
}

func authorizationCodeForNonce(nonce string) string {
	if nonce == "" {
		return "fixed_auth_code_123"
	}
	return "fixed_auth_code_123." + nonce
}

func getTestFile(filename string) string {
	return filepath.Join(fsutils.MustGetThisDir(), "testdata", filename)
}
