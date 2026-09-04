package auth0

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/auth0/go-auth0/v3/management"
	"github.com/auth0/go-auth0/v3/management/option"
	"github.com/auth0/go-jwt-middleware/v3/jwks"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"goyave.dev/goyave/v5"
	"goyave.dev/goyave/v5/lang"
	"goyave.dev/goyave/v5/util/errors"
	"goyave.dev/goyave/v5/util/testutil"
)

type mockUser struct {
	Auth0UserID string
	Email       string
}

type mockUserService struct {
	gotProfile *management.GetUserResponseContent
	gotSubject string
	user       *mockUser
	getErr     error
	createErr  error
}

func (m *mockUserService) CreateFromAuth0(_ context.Context, userProfile *management.GetUserResponseContent) (*mockUser, error) {
	m.gotProfile = userProfile
	return &mockUser{
		Auth0UserID: *userProfile.UserID,
		Email:       *userProfile.Email,
	}, m.createErr
}

func (m *mockUserService) GetBySubject(_ context.Context, subject string) (*mockUser, error) {
	m.gotSubject = subject
	if m.user == nil {
		return nil, gorm.ErrRecordNotFound
	}
	return m.user, m.getErr
}

type testCustomClaims struct {
	CustomField string `json:"custom_field"`
}

func (c *testCustomClaims) Validate(_ context.Context) error {
	if c.CustomField == "" {
		return fmt.Errorf("custom field is required")
	}
	return nil
}

type mockHTTPClient struct {
	gotRequest []*http.Request
	profile    *management.GetUserResponseContent
	response   *http.Response
	err        error
}

func (m *mockHTTPClient) Do(request *http.Request) (*http.Response, error) {
	m.gotRequest = append(m.gotRequest, request)
	if m.response != nil {
		m.response.Body = jsonReader(m.profile)
	}
	return m.response, m.err
}

type oidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

func jsonReader(v any) io.ReadCloser {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return io.NopCloser(bytes.NewBuffer(b))
}

const testKeyID = "test-key-id"

func genreateToken(t *testing.T, tokenBuilder *jwt.Builder, privateKey *rsa.PrivateKey) string {
	token, err := tokenBuilder.Claim("kid", testKeyID).Build()
	require.NoError(t, err)

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), privateKey))
	require.NoError(t, err)
	return string(signed)
}

func setupJWKSServer(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKey, err := jwk.PublicKeyOf(privateKey)
	require.NoError(t, err)

	require.NoError(t, pubKey.Set(jwk.KeyIDKey, testKeyID))
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, string(validator.RS256)))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubKey))

	mux := http.NewServeMux()

	server := httptest.NewServer(mux)
	issuerURL := server.URL + "/"

	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := oidcDiscovery{
			Issuer:  issuerURL,
			JWKSURI: issuerURL + ".well-known/jwks.json",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	t.Cleanup(server.Close)
	return server, privateKey
}

func validateProfile(t *testing.T, want, profile *management.GetUserResponseContent) {
	if want == nil {
		assert.Nil(t, profile)
		return
	}
	// Only check the fields that we actually fill in the tests to avoid making it too verbose
	// We are forced to do that because profile.rawJSON is populated automatically
	assert.Equal(t, want.UserID, profile.UserID)
	assert.Equal(t, want.Email, profile.Email)
}

func validateClaims(t *testing.T, want *testCustomClaims, request *goyave.Request) {
	if want == nil {
		assert.NotContains(t, request.Extra, ExtraAuth0Claims{})
		return
	}
	rawClaims, ok := request.Extra[ExtraAuth0Claims{}]
	if !assert.True(t, ok) {
		return
	}
	claims, ok := rawClaims.(*Claims[*testCustomClaims])
	if !assert.True(t, ok) {
		return
	}
	assert.Equal(t, want, claims.CustomClaims)
}

func TestAppAuthenticator(t *testing.T) {
	cases := []struct {
		desc                 string
		service              *mockUserService
		cfg                  func(issuerDomain string) *Config
		managementHTTPClient *mockHTTPClient
		subjectFunc          func(c *Claims[*testCustomClaims]) string
		tokenBuilder         func(t *testing.T, issuerURL string) *jwt.Builder
		wantInitErr          error
		wantAuthErr          error
		wantUser             *mockUser
		wantSubject          string
		wantCustomClaims     *testCustomClaims
		expectPanic          bool
	}{
		{
			desc: "OK_user_created",
			service: &mockUserService{
				user:      nil,
				createErr: nil,
				getErr:    nil,
			},
			cfg: func(issuerURL string) *Config {
				return &Config{
					Algorithm:     validator.RS256,
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{issuerURL},
					Audiences:     []string{"http://localhost/authorize"},
				}
			},
			managementHTTPClient: &mockHTTPClient{
				profile: &management.GetUserResponseContent{
					UserID: new("auth0|abcdefghijklmnop"),
					Email:  new("johndoe@example.org"),
				},
				response: &http.Response{
					StatusCode: http.StatusOK,
				},
				err: nil,
			},
			tokenBuilder: func(_ *testing.T, issuerURL string) *jwt.Builder {
				issuedAt := time.Now().Add(-time.Second * 30)
				return jwt.NewBuilder().
					Subject("auth0|abcdefghijklmnop").
					Audience([]string{"http://localhost/authorize"}).
					Issuer(issuerURL).
					IssuedAt(issuedAt).
					NotBefore(issuedAt).
					Expiration(time.Now().Add(time.Second*3600)).
					Claim("custom_field", "custom_value") // Custom claim
			},
			wantInitErr: nil,
			wantAuthErr: nil,
			wantUser: &mockUser{
				Auth0UserID: "auth0|abcdefghijklmnop",
				Email:       "johndoe@example.org",
			},
			wantSubject:      "auth0|abcdefghijklmnop",
			wantCustomClaims: &testCustomClaims{CustomField: "custom_value"},
		},
		{
			desc: "OK_user_exists",
			service: &mockUserService{
				user: &mockUser{
					Auth0UserID: "auth0|abcdefghijklmnop",
					Email:       "johndoe@example.org",
				},
				createErr: nil,
				getErr:    nil,
			},
			cfg: func(issuerURL string) *Config {
				return &Config{
					Algorithm:     validator.RS256,
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{issuerURL},
					Audiences:     []string{"http://localhost/authorize"},
				}
			},
			managementHTTPClient: &mockHTTPClient{
				profile:  nil, // We don't expect a call on the management API
				response: nil,
				err:      nil,
			},
			tokenBuilder: func(_ *testing.T, issuerURL string) *jwt.Builder {
				issuedAt := time.Now().Add(-time.Second * 30)
				return jwt.NewBuilder().
					Subject("auth0|abcdefghijklmnop").
					Audience([]string{"http://localhost/authorize"}).
					Issuer(issuerURL).
					IssuedAt(issuedAt).
					NotBefore(issuedAt).
					Expiration(time.Now().Add(time.Second*3600)).
					Claim("custom_field", "custom_value") // Custom claim
			},
			wantInitErr: nil,
			wantAuthErr: nil,
			wantUser: &mockUser{
				Auth0UserID: "auth0|abcdefghijklmnop",
				Email:       "johndoe@example.org",
			},
			wantSubject:      "auth0|abcdefghijklmnop",
			wantCustomClaims: &testCustomClaims{CustomField: "custom_value"},
		},
		{
			desc: "OK_subject_func",
			service: &mockUserService{
				user: &mockUser{
					Auth0UserID: "auth0|123456789",
					Email:       "johndoe@example.org",
				},
				createErr: nil,
				getErr:    nil,
			},
			cfg: func(issuerURL string) *Config {
				return &Config{
					Algorithm:     validator.RS256,
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{issuerURL},
					Audiences:     []string{"http://localhost/authorize"},
				}
			},
			subjectFunc: func(c *Claims[*testCustomClaims]) string {
				return c.CustomClaims.CustomField
			},
			managementHTTPClient: &mockHTTPClient{},
			tokenBuilder: func(_ *testing.T, issuerURL string) *jwt.Builder {
				issuedAt := time.Now().Add(-time.Second * 30)
				return jwt.NewBuilder().
					Subject("auth0|abcdefghijklmnop").
					Audience([]string{"http://localhost/authorize"}).
					Issuer(issuerURL).
					IssuedAt(issuedAt).
					NotBefore(issuedAt).
					Expiration(time.Now().Add(time.Second*3600)).
					Claim("custom_field", "johndoe@example.org")
			},
			wantInitErr: nil,
			wantAuthErr: nil,
			wantUser: &mockUser{
				Auth0UserID: "auth0|123456789",
				Email:       "johndoe@example.org",
			},
			wantSubject:      "johndoe@example.org",
			wantCustomClaims: &testCustomClaims{CustomField: "johndoe@example.org"},
		},
		{
			desc:    "token_expired",
			service: &mockUserService{},
			cfg: func(issuerURL string) *Config {
				return &Config{
					Algorithm:     validator.RS256,
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{issuerURL},
					Audiences:     []string{"http://localhost/authorize"},
				}
			},
			managementHTTPClient: &mockHTTPClient{},
			tokenBuilder: func(_ *testing.T, issuerURL string) *jwt.Builder {
				issuedAt := time.Now().Add(-time.Second * 6000)
				return jwt.NewBuilder().
					Subject("auth0|abcdefghijklmnop").
					Audience([]string{"http://localhost/authorize"}).
					Issuer(issuerURL).
					IssuedAt(issuedAt).
					NotBefore(issuedAt).
					Expiration(time.Now().Add(-time.Second*3600)).
					Claim("custom_field", "custom_value") // Custom claim
			},
			wantInitErr:      nil,
			wantAuthErr:      errors.New(lang.Default.Get("auth.invalid-credentials")),
			wantUser:         nil,
			wantCustomClaims: nil,
		},
		{
			desc:    "invalid_issuer_url",
			service: &mockUserService{},
			cfg: func(_ string) *Config {
				return &Config{
					Algorithm:     validator.RS256,
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{"nota\x7fdomain"},
					Audiences:     []string{"http://localhost/authorize"},
				}
			},
			managementHTTPClient: &mockHTTPClient{},
			wantInitErr:          errors.New("failed to parse issuer URL: "),
		},
		{
			desc:    "jwks_init_failure",
			service: &mockUserService{},
			cfg: func(issuerURL string) *Config {
				return &Config{
					Algorithm:     validator.RS256,
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{issuerURL},
					Audiences:     []string{"http://localhost/authorize"},
					JWKSOptions: []jwks.MultiIssuerProviderOption{
						jwks.WithIssuerKeyConfig("fake_issuer", jwks.IssuerKeyConfig{Algorithm: validator.RS256, Secret: []byte("secret")}),
					},
				}
			},
			managementHTTPClient: &mockHTTPClient{},
			wantInitErr:          errors.New("failed to create JWKS provider: "),
		},
		{
			desc:    "validator_init_failure",
			service: &mockUserService{},
			cfg: func(issuerURL string) *Config {
				return &Config{
					Algorithm:     "not an alg",
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{issuerURL},
					Audiences:     []string{"http://localhost/authorize"},
				}
			},
			managementHTTPClient: &mockHTTPClient{},
			wantInitErr:          errors.New("failed to create validator: "),
		},
		{
			desc: "user_retrieval_error",
			service: &mockUserService{
				user:      &mockUser{},
				createErr: nil,
				getErr:    errors.New("test error"),
			},
			cfg: func(issuerURL string) *Config {
				return &Config{
					Algorithm:     validator.RS256,
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{issuerURL},
					Audiences:     []string{"http://localhost/authorize"},
				}
			},
			managementHTTPClient: &mockHTTPClient{},
			tokenBuilder: func(_ *testing.T, issuerURL string) *jwt.Builder {
				issuedAt := time.Now().Add(-time.Second * 30)
				return jwt.NewBuilder().
					Subject("auth0|abcdefghijklmnop").
					Audience([]string{"http://localhost/authorize"}).
					Issuer(issuerURL).
					IssuedAt(issuedAt).
					NotBefore(issuedAt).
					Expiration(time.Now().Add(time.Second*3600)).
					Claim("custom_field", "custom_value") // Custom claim
			},
			wantInitErr:      nil,
			wantAuthErr:      nil,
			wantUser:         nil,
			wantSubject:      "auth0|abcdefghijklmnop",
			wantCustomClaims: &testCustomClaims{CustomField: "custom_value"},
			expectPanic:      true,
		},
		{
			desc: "user_creation_error",
			service: &mockUserService{
				user:      nil,
				createErr: errors.New("test error"),
				getErr:    nil,
			},
			cfg: func(issuerURL string) *Config {
				return &Config{
					Algorithm:     validator.RS256,
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{issuerURL},
					Audiences:     []string{"http://localhost/authorize"},
				}
			},
			managementHTTPClient: &mockHTTPClient{
				profile: &management.GetUserResponseContent{
					UserID: new("auth0|abcdefghijklmnop"),
					Email:  new("johndoe@example.org"),
				},
				response: &http.Response{
					StatusCode: http.StatusOK,
				},
				err: nil,
			},
			tokenBuilder: func(_ *testing.T, issuerURL string) *jwt.Builder {
				issuedAt := time.Now().Add(-time.Second * 30)
				return jwt.NewBuilder().
					Subject("auth0|abcdefghijklmnop").
					Audience([]string{"http://localhost/authorize"}).
					Issuer(issuerURL).
					IssuedAt(issuedAt).
					NotBefore(issuedAt).
					Expiration(time.Now().Add(time.Second*3600)).
					Claim("custom_field", "custom_value") // Custom claim
			},
			wantInitErr:      nil,
			wantAuthErr:      nil,
			wantUser:         nil,
			wantSubject:      "auth0|abcdefghijklmnop",
			wantCustomClaims: &testCustomClaims{CustomField: "custom_value"},
			expectPanic:      true,
		},
		{
			desc: "management_api_request_error",
			service: &mockUserService{
				user:      nil,
				createErr: nil,
				getErr:    nil,
			},
			cfg: func(issuerURL string) *Config {
				return &Config{
					Algorithm:     validator.RS256,
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{issuerURL},
					Audiences:     []string{"http://localhost/authorize"},
				}
			},
			managementHTTPClient: &mockHTTPClient{
				profile:  nil,
				response: nil,
				err:      errors.New("test error"),
			},
			tokenBuilder: func(_ *testing.T, issuerURL string) *jwt.Builder {
				issuedAt := time.Now().Add(-time.Second * 30)
				return jwt.NewBuilder().
					Subject("auth0|abcdefghijklmnop").
					Audience([]string{"http://localhost/authorize"}).
					Issuer(issuerURL).
					IssuedAt(issuedAt).
					NotBefore(issuedAt).
					Expiration(time.Now().Add(time.Second*3600)).
					Claim("custom_field", "custom_value") // Custom claim
			},
			wantInitErr:      nil,
			wantAuthErr:      nil,
			wantUser:         nil,
			wantSubject:      "auth0|abcdefghijklmnop",
			wantCustomClaims: &testCustomClaims{CustomField: "custom_value"},
			expectPanic:      true,
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			jwksServer, privateKey := setupJWKSServer(t)
			issuerURL := jwksServer.URL + "/"

			cfg := c.cfg(jwksServer.Listener.Addr().String())
			cfg.useHTTP = true
			cfg.ManagementOptions = append(cfg.ManagementOptions, option.WithHTTPClient(c.managementHTTPClient))
			authenticator, err := NewAppAuthenticator[mockUser, testCustomClaims](c.service, cfg)
			if c.wantInitErr != nil {
				require.Error(t, err)
				require.ErrorContains(t, err, c.wantInitErr.Error())
				return
			} else {
				require.NoError(t, err)
			}

			assert.Same(t, cfg, authenticator.config)
			assert.Equal(t, c.service, authenticator.userService)
			assert.NotNil(t, authenticator.validator)
			assert.NotNil(t, authenticator.management)

			if c.subjectFunc != nil {
				authenticator.SubjectFunc = c.subjectFunc
			}

			request := testutil.NewTestRequest(http.MethodGet, "/profile", nil)
			request.Lang = lang.Default
			if c.tokenBuilder != nil {
				token := genreateToken(t, c.tokenBuilder(t, issuerURL), privateKey)
				request.Header().Set("Authorization", "Bearer "+token)
			}
			var user *mockUser
			if c.expectPanic {
				assert.Panics(t, func() {
					user, err = authenticator.Authenticate(request)
				})
			} else {
				assert.NotPanics(t, func() {
					user, err = authenticator.Authenticate(request)
				})
			}
			if c.wantAuthErr != nil {
				require.Error(t, err)
				require.ErrorContains(t, err, c.wantAuthErr.Error())
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, c.wantUser, user)
			if c.wantUser != nil {
				assert.Equal(t, c.wantSubject, c.service.gotSubject)
			}
			validateProfile(t, c.managementHTTPClient.profile, c.service.gotProfile)
			validateClaims(t, c.wantCustomClaims, request)
		})
	}
}

func TestAuthenticator(t *testing.T) {
	cases := []struct {
		desc                 string
		cfg                  func(issuerDomain string) *Config
		managementHTTPClient *mockHTTPClient
		tokenBuilder         func(t *testing.T, issuerURL string) *jwt.Builder
		wantInitErr          error
		wantAuthErr          error
		wantCustomClaims     *testCustomClaims
		expectPanic          bool
	}{
		{
			desc: "OK",
			cfg: func(issuerURL string) *Config {
				return &Config{
					Algorithm:     validator.RS256,
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{issuerURL},
					Audiences:     []string{"http://localhost/authorize"},
				}
			},
			managementHTTPClient: &mockHTTPClient{
				profile: &management.GetUserResponseContent{
					UserID: new("auth0|abcdefghijklmnop"),
					Email:  new("johndoe@example.org"),
				},
				response: &http.Response{
					StatusCode: http.StatusOK,
				},
				err: nil,
			},
			tokenBuilder: func(_ *testing.T, issuerURL string) *jwt.Builder {
				issuedAt := time.Now().Add(-time.Second * 30)
				return jwt.NewBuilder().
					Subject("auth0|abcdefghijklmnop").
					Audience([]string{"http://localhost/authorize"}).
					Issuer(issuerURL).
					IssuedAt(issuedAt).
					NotBefore(issuedAt).
					Expiration(time.Now().Add(time.Second*3600)).
					Claim("custom_field", "custom_value") // Custom claim
			},
			wantInitErr:      nil,
			wantAuthErr:      nil,
			wantCustomClaims: &testCustomClaims{CustomField: "custom_value"},
		},
		{
			desc: "token_expired",
			cfg: func(issuerURL string) *Config {
				return &Config{
					Algorithm:     validator.RS256,
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{issuerURL},
					Audiences:     []string{"http://localhost/authorize"},
				}
			},
			managementHTTPClient: &mockHTTPClient{},
			tokenBuilder: func(_ *testing.T, issuerURL string) *jwt.Builder {
				issuedAt := time.Now().Add(-time.Second * 6000)
				return jwt.NewBuilder().
					Subject("auth0|abcdefghijklmnop").
					Audience([]string{"http://localhost/authorize"}).
					Issuer(issuerURL).
					IssuedAt(issuedAt).
					NotBefore(issuedAt).
					Expiration(time.Now().Add(-time.Second*3600)).
					Claim("custom_field", "custom_value") // Custom claim
			},
			wantInitErr:      nil,
			wantAuthErr:      errors.New(lang.Default.Get("auth.invalid-credentials")),
			wantCustomClaims: nil,
		},
		{
			desc: "invalid_issuer_url",
			cfg: func(_ string) *Config {
				return &Config{
					Algorithm:     validator.RS256,
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{"nota\x7fdomain"},
					Audiences:     []string{"http://localhost/authorize"},
				}
			},
			managementHTTPClient: &mockHTTPClient{},
			wantInitErr:          errors.New("failed to parse issuer URL: "),
		},
		{
			desc: "jwks_init_failure",
			cfg: func(issuerURL string) *Config {
				return &Config{
					Algorithm:     validator.RS256,
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{issuerURL},
					Audiences:     []string{"http://localhost/authorize"},
					JWKSOptions: []jwks.MultiIssuerProviderOption{
						jwks.WithIssuerKeyConfig("fake_issuer", jwks.IssuerKeyConfig{Algorithm: validator.RS256, Secret: []byte("secret")}),
					},
				}
			},
			managementHTTPClient: &mockHTTPClient{},
			wantInitErr:          errors.New("failed to create JWKS provider: "),
		},
		{
			desc: "validator_init_failure",
			cfg: func(issuerURL string) *Config {
				return &Config{
					Algorithm:     "not an alg",
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{issuerURL},
					Audiences:     []string{"http://localhost/authorize"},
				}
			},
			managementHTTPClient: &mockHTTPClient{},
			wantInitErr:          errors.New("failed to create validator: "),
		},
		{
			desc: "management_api_request_error",
			cfg: func(issuerURL string) *Config {
				return &Config{
					Algorithm:     validator.RS256,
					ClientID:      "test-client-id",
					ClientSecret:  "test-client-secret",
					IssuerDomains: []string{issuerURL},
					Audiences:     []string{"http://localhost/authorize"},
				}
			},
			managementHTTPClient: &mockHTTPClient{
				profile:  nil,
				response: nil,
				err:      errors.New("test error"),
			},
			tokenBuilder: func(_ *testing.T, issuerURL string) *jwt.Builder {
				issuedAt := time.Now().Add(-time.Second * 30)
				return jwt.NewBuilder().
					Subject("auth0|abcdefghijklmnop").
					Audience([]string{"http://localhost/authorize"}).
					Issuer(issuerURL).
					IssuedAt(issuedAt).
					NotBefore(issuedAt).
					Expiration(time.Now().Add(time.Second*3600)).
					Claim("custom_field", "custom_value") // Custom claim
			},
			wantInitErr:      nil,
			wantAuthErr:      nil,
			wantCustomClaims: &testCustomClaims{CustomField: "custom_value"},
			expectPanic:      true,
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			jwksServer, privateKey := setupJWKSServer(t)
			issuerURL := jwksServer.URL + "/"

			cfg := c.cfg(jwksServer.Listener.Addr().String())
			cfg.useHTTP = true
			cfg.ManagementOptions = append(cfg.ManagementOptions, option.WithHTTPClient(c.managementHTTPClient))
			authenticator, err := NewAuthenticator[testCustomClaims](cfg)
			if c.wantInitErr != nil {
				require.Error(t, err)
				require.ErrorContains(t, err, c.wantInitErr.Error())
				return
			} else {
				require.NoError(t, err)
			}

			assert.Same(t, cfg, authenticator.config)
			assert.NotNil(t, authenticator.validator)
			assert.NotNil(t, authenticator.management)

			request := testutil.NewTestRequest(http.MethodGet, "/profile", nil)
			request.Lang = lang.Default
			if c.tokenBuilder != nil {
				token := genreateToken(t, c.tokenBuilder(t, issuerURL), privateKey)
				request.Header().Set("Authorization", "Bearer "+token)
			}
			var user *management.GetUserResponseContent
			if c.expectPanic {
				assert.Panics(t, func() {
					user, err = authenticator.Authenticate(request)
				})
			} else {
				assert.NotPanics(t, func() {
					user, err = authenticator.Authenticate(request)
				})
			}
			if c.wantAuthErr != nil {
				require.Error(t, err)
				require.ErrorContains(t, err, c.wantAuthErr.Error())
			} else {
				require.NoError(t, err)
			}
			validateProfile(t, c.managementHTTPClient.profile, user)
			validateClaims(t, c.wantCustomClaims, request)
		})
	}
}
