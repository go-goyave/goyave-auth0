package auth0

import (
	"context"
	stderrors "errors"
	"net/url"
	"time"

	"github.com/auth0/go-auth0/v3/management"
	managementClient "github.com/auth0/go-auth0/v3/management/client"
	"github.com/auth0/go-auth0/v3/management/option"
	"github.com/auth0/go-jwt-middleware/v3/jwks"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	"gorm.io/gorm"
	"goyave.dev/goyave/v5"
	"goyave.dev/goyave/v5/util/errors"
)

// UserService is the dependency of [Authenticator].
type UserService[T any] interface {
	// GetBySubject returns a user stored in database using the token's subject.
	// See [Authenticator.SubjectFunc].
	GetBySubject(ctx context.Context, subject string) (*T, error)
	// CreateFromAuth0 creates a user from the [management.GetUserResponseContent] retrieved from
	// Auth0 using the authenticated user's access token and the Management API.
	// This is called automatically if [UserService.FindBySubject] returns [gorm.ErrRecordNotFound], indicating
	// the user doesn't exist in the database and that it's probably their first successful login.
	//
	// Important: your application must have the "read:users" permission on the Auth0 Management API.
	CreateFromAuth0(ctx context.Context, userInfo *management.GetUserResponseContent) (*T, error)
}

// Authenticator Auth0 [goyave.dev/goyave/v5/auth.Authenticator] implementation.
type Authenticator[U any, C any, CC CustomClaims[C]] struct {
	goyave.Component

	UserService UserService[U]

	config     *Config
	validator  *validator.Validator
	management map[string]*managementClient.Management // map issuer url with management client

	// SubjectFunc returns the value of the subject to use for user
	// retrieval. The returned value is forwarded to the [UserService].
	// By default, it returns the [validator.RegisteredClaims.Subject] (`sub` JWT claim).
	SubjectFunc func(c *Claims[CC]) string
}

// NewAuthenticator setup a JWKS caching provider, a JWT validator and a Goyave authenticator.
// If your JWT isn't expected to hold custom claims, use [NoCustomClaims] for type C.
// Type C must NOT be a pointer. Type CC can be inferred, no need to explicitly specify it.
func NewAuthenticator[U any, C any, CC CustomClaims[C]](userService UserService[U], cfg *Config) (*Authenticator[U, C, CC], error) {
	issuerURLs, err := generateIssuerURLs(cfg.IssuerDomains)
	if err != nil {
		return nil, errors.New(err)
	}

	cacheTTL := 15 * time.Minute
	if cfg.CacheTTL != 0 {
		cacheTTL = time.Duration(cfg.CacheTTL) * time.Second
	}

	jwksOpts := append(
		[]jwks.MultiIssuerProviderOption{jwks.WithMultiIssuerCacheTTL(cacheTTL)},
		cfg.JWKSOptions...,
	)
	provider, err := jwks.NewMultiIssuerProvider(jwksOpts...)

	if err != nil {
		return nil, errors.Errorf("failed to create JWKS provider: %w", err)
	}

	opts := append([]validator.Option{
		validator.WithKeyFunc(provider.KeyFunc),
		validator.WithAlgorithm(cfg.Algorithm),
		validator.WithIssuers(issuerURLs),
		validator.WithAudiences(cfg.Audiences),
		validator.WithAllowedClockSkew(30 * time.Second),
		validator.WithCustomClaims(func() CC {
			return CC(new(C))
		}),
	}, cfg.ValidatorOptions...)
	jwtValidator, err := validator.New(opts...)
	if err != nil {
		return nil, errors.Errorf("failed to create validator: %w", err)
	}

	management := make(map[string]*managementClient.Management, len(cfg.IssuerDomains))
	for _, url := range issuerURLs {
		managementOpts := append(
			[]option.RequestOption{option.WithClientCredentials(context.Background(), cfg.ClientID, cfg.ClientSecret)},
			cfg.ManagementOptions...,
		)
		client, err := managementClient.New(url, managementOpts...)
		if err != nil {
			return nil, errors.New(err)
		}
		management[url] = client
	}

	return &Authenticator[U, C, CC]{
		config:      cfg,
		UserService: userService,
		validator:   jwtValidator,
		management:  management,
	}, nil
}

func generateIssuerURLs(domains []string) ([]string, error) {
	urls := make([]string, 0, len(domains))
	for _, domain := range domains {
		url, err := url.Parse("https://" + domain + "/")
		if err != nil {
			return nil, errors.Errorf("failed to parse issuer URL: %w", err)
		}
		urls = append(urls, url.String())
	}
	return urls, nil
}

// Authenticate implementation of [goyave.dev/goyave/v5/auth.Authenticator.Authenticate].
func (a *Authenticator[U, C, CC]) Authenticate(request *goyave.Request) (*U, error) {
	token, ok := request.BearerToken()
	// Note: DPoP is not supported

	if !ok {
		return nil, stderrors.New(request.Lang.Get("auth.no-credentials-provided"))
	}

	rawClaims, err := a.validator.ValidateToken(request.Context(), token)
	if err != nil {
		return nil, stderrors.New(request.Lang.Get("auth.invalid-credentials"))
	}

	validatedClaims, ok := rawClaims.(*validator.ValidatedClaims)
	if !ok {
		return nil, stderrors.New(request.Lang.Get("auth.invalid-credentials"))
	}

	customClaims, ok := validatedClaims.CustomClaims.(CC)
	if !ok {
		return nil, stderrors.New(request.Lang.Get("auth.invalid-credentials"))
	}

	claims := &Claims[CC]{
		RegisteredClaims: validatedClaims.RegisteredClaims,
		CustomClaims:     customClaims,
	}

	request.Extra[ExtraAuth0Claims{}] = claims // Claims can be used later for permissions/scopes

	// TODO allow retrieving user identity through profile too (simply by using the claims)
	user, err := a.UserService.GetBySubject(request.Context(), a.getSubject(claims))
	if err != nil {
		if stderrors.Is(err, gorm.ErrRecordNotFound) {
			// First time this user logs in, create it in the application database.
			return a.createUser(request.Context(), claims)
		}
		panic(errors.New(err)) // TODO for v6, change this: return error instead of panicking
		// return nil, errors.New(err)
	}

	return user, nil
}

func (a *Authenticator[U, C, CC]) getSubject(claims *Claims[CC]) string {
	if a.SubjectFunc == nil {
		return claims.RegisteredClaims.Subject
	}
	return a.SubjectFunc(claims)
}

func (a *Authenticator[U, C, CC]) createUser(ctx context.Context, claims *Claims[CC]) (*U, error) {
	managementClient, ok := a.management[claims.RegisteredClaims.Issuer]
	if !ok {
		panic(errors.Errorf("could not find a management API client for issuer domain %q", claims.RegisteredClaims.Issuer)) // TODO for v6, change this: return error instead of panicking
		// return nil, errors.Errorf("could not find a management API client for issuer domain %q", claims.RegisteredClaims.Issuer)
	}

	userData, err := managementClient.Users.Get(ctx, claims.RegisteredClaims.Subject, &management.GetUserRequestParameters{})
	if err != nil {
		panic(errors.New(err)) // TODO for v6, change this: return error instead of panicking
		// return nil, errors.New(err)
	}

	user, err := a.UserService.CreateFromAuth0(ctx, userData)
	if err != nil {
		panic(errors.New(err)) // TODO for v6, change this: return error instead of panicking
		// return nil, errors.New(err)
	}
	return user, nil
}
