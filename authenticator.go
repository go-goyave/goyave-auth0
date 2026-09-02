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
	FindBySubject(ctx context.Context, subject string) (*T, error)
}

// Authenticator Auth0 [goyave.dev/goyave/v5/auth.Authenticator] implementation.
type Authenticator[U any, C any, CC CustomClaims[C]] struct {
	goyave.Component

	UserService UserService[U]

	config    *Config
	validator *validator.Validator

	// SubjectFunc returns the value of the subject to use for user
	// retrieval. The returned value is forwarded to the [UserService].
	// By default, it returns the [validator.RegisteredClaims.Subject] (`sub` JWT claim).
	SubjectFunc func(c *Claims[CC]) string
}

// NewAuthenticator setup a JWKS caching provider, a JWT validator and a Goyave authenticator.
// If your JWT isn't expected to hold custom claims, use [NoCustomClaims] for type C.
// Type C must NOT be a pointer. Type CC can be inferred, no need to explicitly specify it.
func NewAuthenticator[U any, C any, CC CustomClaims[C]](userService UserService[U], cfg *Config, validatorOptions ...validator.Option) (*Authenticator[U, C, CC], error) {
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
		validator.WithCustomClaims(func() CC {
			return CC(new(C))
		}),
		// validator.WithCustomClaims[*C](newCustomClaims[C, *C]),
	}, validatorOptions...)
	jwtValidator, err := validator.New(opts...)
	if err != nil {
		return nil, errors.Errorf("failed to create validator: %w", err)
	}

	return &Authenticator[U, C, CC]{
		config:      cfg,
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

	user, err := a.UserService.FindBySubject(request.Context(), a.getSubject(claims))
	if err != nil {
		if stderrors.Is(err, gorm.ErrRecordNotFound) {
			return nil, stderrors.New(request.Lang.Get("auth.invalid-credentials"))
		}
		panic(errors.New(err)) // TODO for v6, change this: return error instead of panicking
	}

	return user, nil
}

func (a *Authenticator[U, C, CC]) getSubject(claims *Claims[CC]) string {
	if a.SubjectFunc == nil {
		return claims.RegisteredClaims.Subject
	}
	return a.SubjectFunc(claims)
}
