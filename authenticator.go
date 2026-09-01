package auth0

import (
	"context"
	stderrors "errors"
	"net/url"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/jwks"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	"gorm.io/gorm"
	"goyave.dev/goyave/v5"
	"goyave.dev/goyave/v5/util/errors"
)

// UserService is the dependency of [Authenticator] used to retrieve a user
// using a JWT subject claim. See [Authenticator.SubjectFunc].
type UserService[T any] interface {
	FindUserBySubject(ctx context.Context, subject string) (*T, error)
}

// Authenticator Auth0 [goyave.dev/goyave/v5/auth.Authenticator] implementation.
type Authenticator[U any, C validator.CustomClaims] struct {
	goyave.Component

	UserService UserService[U]

	Config    *Config
	validator *validator.Validator

	// SubjectFunc returns the value of the subject to use for user
	// retrieval. The returned value is forwarded to the [UserService].
	// By default, it returns the [validator.RegisteredClaims.Subject] (`sub` JWT claim).
	SubjectFunc func(c *Claims[C]) string
}

// NewAuthenticator setup a JWKS caching provider, a JWT validator and a Goyave authenticator.
// If your JWT isn't expected to hold custom claims, use [NoCustomClaims] for type C.
// Type C must be a pointer.
func NewAuthenticator[U any, C validator.CustomClaims](userService UserService[U], cfg *Config, validatorOptions ...validator.Option) (*Authenticator[U, C], error) {
	issuerURLs, err := generateIssuerURLs(cfg.IssuerDomains)
	if err != nil {
		return nil, errors.New(err)
	}

	cacheTTL := 15 * time.Minute
	if cfg.CacheTTL != 0 {
		cacheTTL = time.Duration(cfg.CacheTTL) * time.Second
	}

	provider, err := jwks.NewMultiIssuerProvider(
		jwks.WithMultiIssuerCacheTTL(cacheTTL),
		// TODO expose custom options for the provider
	)

	if err != nil {
		return nil, errors.Errorf("failed to create JWKS provider: %w", err)
	}

	opts := append([]validator.Option{
		validator.WithKeyFunc(provider.KeyFunc),
		validator.WithAlgorithm(cfg.Algorithm),
		validator.WithIssuers(issuerURLs),
		validator.WithAudiences(cfg.Audiences),
		validator.WithAllowedClockSkew(30 * time.Second),
		validator.WithCustomClaims(func() C { // TODO test this, likely error because of nil pointer
			var customClaims C
			return customClaims
		}),
	}, validatorOptions...)
	jwtValidator, err := validator.New(opts...)
	if err != nil {
		return nil, errors.Errorf("failed to create validator: %w", err)
	}

	return &Authenticator[U, C]{
		Config:      cfg,
		UserService: userService,
		validator:   jwtValidator,
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
func (a *Authenticator[U, C]) Authenticate(request *goyave.Request) (*U, error) {
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

	customClaims, ok := validatedClaims.CustomClaims.(C)
	if !ok {
		return nil, stderrors.New(request.Lang.Get("auth.invalid-credentials"))
	}

	claims := &Claims[C]{
		RegisteredClaims: validatedClaims.RegisteredClaims,
		CustomClaims:     customClaims,
	}

	request.Extra[ExtraAuth0Claims{}] = claims // Claims can be used later for permissions/scopes

	user, err := a.UserService.FindUserBySubject(request.Context(), a.getSubject(claims))
	if err != nil {
		if stderrors.Is(err, gorm.ErrRecordNotFound) {
			return nil, stderrors.New(request.Lang.Get("auth.invalid-credentials"))
		}
		panic(errors.New(err)) // TODO for v6, change this: return error instead of panicking
	}

	return user, nil
}

func (a *Authenticator[U, C]) getSubject(claims *Claims[C]) string {
	if a.SubjectFunc == nil {
		return claims.RegisteredClaims.Subject
	}
	return a.SubjectFunc(claims)
}
