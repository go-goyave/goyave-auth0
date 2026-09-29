package auth0

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/auth0/go-auth0/v3/management"
	managementClient "github.com/auth0/go-auth0/v3/management/client"
	"github.com/auth0/go-auth0/v3/management/option"
	"github.com/auth0/go-jwt-middleware/v3/jwks"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	"gorm.io/gorm"
	"goyave.dev/goyave/v6"
	"goyave.dev/goyave/v6/util/errwrap"
)

// authenticator common implementation shared between [AppAuthenticator] and [Authenticator]. Only validates the token.
type authenticator[U any, C any, CC CustomClaims[C]] struct {
	config     *Config
	validator  *validator.Validator
	management map[string]*managementClient.Management // map issuer url with management client
}

func newAuthenticator[U any, C any, CC CustomClaims[C]](cfg *Config, opts ...Option) (authenticator[U, C, CC], error) {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	issuerURLs, err := generateIssuerURLs(cfg.IssuerDomains, cfg.useHTTP)
	if err != nil {
		return authenticator[U, C, CC]{}, errwrap.New(err)
	}

	cacheTTL := 15 * time.Minute
	if cfg.CacheTTL != 0 {
		cacheTTL = time.Duration(cfg.CacheTTL) * time.Second
	}

	jwksOpts := append(
		[]jwks.MultiIssuerProviderOption{jwks.WithMultiIssuerCacheTTL(cacheTTL)},
		o.jwksOptions...,
	)
	provider, err := jwks.NewMultiIssuerProvider(jwksOpts...)
	if err != nil {
		return authenticator[U, C, CC]{}, errwrap.Errorf("failed to create JWKS provider: %w", err)
	}

	validatorOpts := append([]validator.Option{
		validator.WithKeyFunc(provider.KeyFunc),
		validator.WithAlgorithm(cfg.Algorithm),
		validator.WithIssuers(issuerURLs),
		validator.WithAudiences(cfg.Audiences),
		validator.WithAllowedClockSkew(30 * time.Second),
		validator.WithCustomClaims(func() CC {
			return CC(new(C))
		}),
	}, o.validatorOptions...)
	jwtValidator, err := validator.New(validatorOpts...)
	if err != nil {
		return authenticator[U, C, CC]{}, errwrap.Errorf("failed to create validator: %w", err)
	}

	management := make(map[string]*managementClient.Management, len(cfg.IssuerDomains))
	for _, url := range issuerURLs {
		managementOpts := append(
			[]option.RequestOption{option.WithClientCredentials(context.Background(), cfg.ClientID, cfg.ClientSecret)},
			o.managementOptions...,
		)
		client, err := managementClient.New(url, managementOpts...)
		if err != nil {
			return authenticator[U, C, CC]{}, errwrap.New(err)
		}
		management[url] = client
	}

	return authenticator[U, C, CC]{
		config:     cfg,
		validator:  jwtValidator,
		management: management,
	}, nil
}

func generateIssuerURLs(domains []string, useHTTP bool) ([]string, error) {
	protocol := "https"
	if useHTTP {
		protocol = "http"
	}
	urls := make([]string, 0, len(domains))
	for _, domain := range domains {
		url, err := url.Parse(protocol + "://" + domain + "/")
		if err != nil {
			return nil, errwrap.Errorf("failed to parse issuer URL: %w", err)
		}
		urls = append(urls, url.String())
	}
	return urls, nil
}

// authenticate implementation of [goyave.dev/goyave/v6/auth.Authenticator.Authenticate].
func (a *authenticator[U, C, CC]) authenticate(request *goyave.Request) (*Claims[CC], error) {
	token, ok := request.BearerToken()
	// Note: DPoP is not supported
	// TODO support DPoP later

	if !ok {
		return nil, goyave.Unauthorized(request.Lang.Get("auth.no-credentials-provided"))
	}

	rawClaims, err := a.validator.ValidateToken(request.Context(), token)
	if err != nil {
		return nil, goyave.Unauthorized(request.Lang.Get("auth.invalid-credentials"))
	}

	validatedClaims, ok := rawClaims.(*validator.ValidatedClaims)
	if !ok {
		return nil, goyave.Unauthorized(request.Lang.Get("auth.invalid-credentials"))
	}

	customClaims, ok := validatedClaims.CustomClaims.(CC)
	if !ok {
		return nil, goyave.Unauthorized(request.Lang.Get("auth.invalid-credentials"))
	}

	claims := &Claims[CC]{
		RegisteredClaims: validatedClaims.RegisteredClaims,
		CustomClaims:     customClaims,
	}

	request.Extra[ExtraAuth0Claims{}] = claims // Claims can be used later for permissions/scopes
	return claims, nil
}

func (a *authenticator[U, C, CC]) getUser(ctx context.Context, claims *Claims[CC]) (*management.GetUserResponseContent, error) {
	managementClient, ok := a.management[claims.RegisteredClaims.Issuer]
	if !ok {
		return nil, errwrap.Errorf("could not find a Management API client for issuer domain %q", claims.RegisteredClaims.Issuer)
	}

	userData, err := managementClient.Users.Get(ctx, claims.RegisteredClaims.Subject, &management.GetUserRequestParameters{})
	if err != nil {
		return nil, errwrap.New(err)
	}
	return userData, nil
}

// UserService is the dependency of [AppAuthenticator].
type UserService[T any] interface {
	// GetBySubject returns a user stored in database using the token's subject.
	// See [AppAuthenticator.SubjectFunc].
	GetBySubject(ctx context.Context, subject string) (*T, error)
	// CreateFromAuth0 creates a user from the [management.GetUserResponseContent] retrieved from
	// Auth0 using the authenticated user's access token and the Management API.
	// This is called automatically if [UserService.FindBySubject] returns [gorm.ErrRecordNotFound], indicating
	// the user doesn't exist in the database and that it's probably their first successful login.
	CreateFromAuth0(ctx context.Context, userProfile *management.GetUserResponseContent) (*T, error)
}

// AppAuthenticator Auth0 [goyave.dev/goyave/v6/auth.Authenticator] implementation
// sourcing the user from the application database.
type AppAuthenticator[U any, C any, CC CustomClaims[C]] struct {
	authenticator[U, C, CC]

	userService UserService[U]

	// SubjectFunc returns the value of the subject to use for user
	// retrieval. The returned value is forwarded to the [UserService].
	// By default, it returns the [validator.RegisteredClaims.Subject] (`sub` JWT claim).
	SubjectFunc func(c *Claims[CC]) string
}

// NewAppAuthenticator create a new Goyave authenticator for Auth0-issued tokens.
//
// Once the token is validated, sources the user from the application database using the token's subject.
// If the token is valid but the user doesn't exist in the application database, user profile is retrieved
// from the Auth0 Management API and inserted into the application database.
//
// Important: your application must have the "read:users" permission on the Auth0 Management API.
//
// If your JWT isn't expected to hold custom claims, use [NoCustomClaims] for type C.
// Type C must NOT be a pointer. Type CC can be inferred, no need to explicitly specify it.
func NewAppAuthenticator[U any, C any, CC CustomClaims[C]](userService UserService[U], cfg *Config, opts ...Option) (*AppAuthenticator[U, C, CC], error) {
	a, err := newAuthenticator[U, C, CC](cfg, opts...)
	if err != nil {
		return nil, errwrap.New(err)
	}

	return &AppAuthenticator[U, C, CC]{
		authenticator: a,
		userService:   userService,
	}, nil
}

func (a *AppAuthenticator[U, C, CC]) Authenticate(request *goyave.Request) (*U, error) {
	claims, err := a.authenticate(request)
	if err != nil {
		return nil, err
	}

	user, err := a.userService.GetBySubject(request.Context(), a.getSubject(claims))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// First time this user logs in, create it in the application database.
			return a.createUser(request.Context(), claims)
		}
		return nil, errwrap.New(err)
	}
	return user, nil
}

func (a *AppAuthenticator[U, C, CC]) getSubject(claims *Claims[CC]) string {
	if a.SubjectFunc == nil {
		return claims.RegisteredClaims.Subject
	}
	return a.SubjectFunc(claims)
}

func (a *AppAuthenticator[U, C, CC]) createUser(ctx context.Context, claims *Claims[CC]) (*U, error) {
	userData, err := a.getUser(ctx, claims)
	if err != nil {
		return nil, errwrap.New(err)
	}

	user, err := a.userService.CreateFromAuth0(ctx, userData)
	if err != nil {
		return nil, errwrap.New(err)
	}
	return user, nil
}

// Authenticator Auth0 [goyave.dev/goyave/v6/auth.Authenticator] implementation
// sourcing the user from the Auth0 user database using the Management API.
type Authenticator[C any, CC CustomClaims[C]] struct {
	authenticator[*management.GetUserResponseContent, C, CC]
}

// NewAuthenticator create a new Goyave authenticator for Auth0-issued tokens.
//
// Once the token is validated, sources the user from the Auth0 user database using the Management API.
//
// Important: your application must have the "read:users" permission on the Auth0 Management API.
//
// If your JWT isn't expected to hold custom claims, use [NoCustomClaims] for type C.
// Type C must NOT be a pointer. Type CC can be inferred, no need to explicitly specify it.
func NewAuthenticator[C any, CC CustomClaims[C]](cfg *Config, opts ...Option) (*Authenticator[C, CC], error) {
	a, err := newAuthenticator[*management.GetUserResponseContent, C, CC](cfg, opts...)
	if err != nil {
		return nil, errwrap.New(err)
	}

	return &Authenticator[C, CC]{
		authenticator: a,
	}, nil
}

func (a *Authenticator[C, CC]) Authenticate(request *goyave.Request) (*management.GetUserResponseContent, error) {
	claims, err := a.authenticate(request)
	if err != nil {
		return nil, err
	}

	user, err := a.getUser(request.Context(), claims)
	if err != nil {
		return nil, errwrap.New(err)
	}
	return user, nil
}
