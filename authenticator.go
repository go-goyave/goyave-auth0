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
	"goyave.dev/goyave/v5/auth"
	"goyave.dev/goyave/v5/util/errors"
)

type UserService[T any, C validator.CustomClaims] interface {
	// TODO User service depending on JWT claims isn't ideal. It should receive the subject.
	// If developer doesn't want to use Subject, or use a custom claim provide an option on the
	// Authenticator to select the claim to use as subject (func).
	FindUserByClaims(ctx context.Context, claims *Claims[C]) (*T, error)
}

type Authenticator[U any, C validator.CustomClaims] struct {
	goyave.Component

	UserService UserService[U, C]

	Config    *Config
	validator *validator.Validator
}

type Config struct {
	Domain   string
	Audience string

	Algorithm validator.SignatureAlgorithm // TODO type incompatible with v6 Config by default (need to create a validator for this). Not a problem for v5.

	CacheTTL int
}

// TODO register config entries for v5

func NewAuthenticator[U any, C validator.CustomClaims](userService UserService[U, C], cfg *Config, validatorOptions ...validator.Option) (*Authenticator[U, C], error) { // TODO try it on blog-example
	issuerURL, err := url.Parse("https://" + cfg.Domain + "/")
	if err != nil {
		return nil, errors.Errorf("failed to parse issuer URL: %w", err)
	}

	cacheTTL := 5 * time.Minute
	if cfg.CacheTTL != 0 {
		cacheTTL = time.Duration(cfg.CacheTTL) * time.Second
	}

	provider, err := jwks.NewCachingProvider(
		jwks.WithIssuerURL(issuerURL),
		jwks.WithCacheTTL(cacheTTL),
	)
	if err != nil {
		return nil, errors.Errorf("failed to create JWKS provider: %w", err)
	}

	opts := append([]validator.Option{
		validator.WithKeyFunc(provider.KeyFunc),
		validator.WithAlgorithm(cfg.Algorithm),
		validator.WithIssuer(issuerURL.String()),
		validator.WithAudience(cfg.Audience),
		// TODO make it possible to skip this option
		// maybe with CustomClaimsAuthenticator and Authenticator so no problem with generics?
		// Or create a type "NoClaims" that just discards custom claims?
		validator.WithCustomClaims(func() validator.CustomClaims {
			var customClaims C
			return customClaims
		}),
		validator.WithAllowedClockSkew(30 * time.Second),
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
		return nil, stderrors.New(request.Lang.Get("auth.invalid-claims")) // TODO lang entry invalid claims
	}

	customClaims, ok := validatedClaims.CustomClaims.(C)
	if !ok {
		return nil, stderrors.New(request.Lang.Get("auth.invalid-claims")) // TODO lang entry invalid claims
	}

	claims := &Claims[C]{
		RegisteredClaims: validatedClaims.RegisteredClaims,
		CustomClaims:     customClaims,
	}

	request.Extra[auth.ExtraJWTClaims{}] = claims // Claims can be used later for permissions/scopes

	user, err := a.UserService.FindUserByClaims(request.Context(), claims)
	if err != nil {
		if stderrors.Is(err, gorm.ErrRecordNotFound) {
			return nil, stderrors.New(request.Lang.Get("auth.invalid-credentials"))
		}
		panic(errors.New(err)) // TODO for v6, change this: return error instead of panicking
	}

	return user, nil
}
