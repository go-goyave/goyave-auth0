package auth0

import (
	"context"
	"errors"
	"net/http"

	"github.com/auth0/go-jwt-middleware/v3/validator"
	"goyave.dev/goyave/v5"
)

// MetaScope route meta associated with a string value indicating the
// authenticated user's required scope to access it.
// Use in combination with the [ScopeMiddleware].
const MetaScope = "goyave.auth0.scope"

// ExtraAuth0Claims key for request extra storing [Claims].
// Set by the [Authenticator].
type ExtraAuth0Claims struct{}

// Claims storing registered and custom JWT claims.
type Claims[T validator.CustomClaims] struct {
	RegisteredClaims validator.RegisteredClaims
	CustomClaims     T
}

// NoCustomClaims represents empty custom JWT claims.
// Use it when your tokens don't contain any custom claim and when
// registered claims are sufficient.
type NoCustomClaims map[string]any

func (NoCustomClaims) Validate(_ context.Context) error {
	return nil
}

// ScopeClaims extension of custom claims that hold scope permissions information.
type ScopeClaims interface {
	validator.CustomClaims
	HasScope(scope string) bool
}

// ScopeMiddleware permission middleware for scope permissions and route restriction.
// It uses [MetaScope] to find the required scope for the current route and validates the
// claims against it. The claims are retrieved from the request's extras with the [ExtraAuth0Claims] key.
type ScopeMiddleware[C ScopeClaims] struct {
	goyave.Component

	// OnForbidden custom handler invoked when the authenticated user
	// doesn't have the required scope.
	//
	// Use if you want to customize the response instead of relying on the 403 status handler.
	//
	// Forbidden response status is always set by the middleware and shouldn't
	// be overridden by this handler.
	OnForbidden goyave.Handler
}

func NewScopeMiddleware[C ScopeClaims]() *ScopeMiddleware[C] {
	return &ScopeMiddleware[C]{}
}

func (m *ScopeMiddleware[C]) Handle(next goyave.Handler) goyave.Handler {
	return func(response *goyave.Response, request *goyave.Request) {
		scope, ok := request.Route.LookupMeta(MetaScope)
		if !ok {
			next(response, request)
			return
		}
		scopeStr, _ := scope.(string)

		claims, ok := request.Extra[ExtraAuth0Claims{}].(*Claims[C])
		if !ok {
			response.Error(errors.New("ScopeMiddleware: missing Auth0 claims in the request extra or incorrect type"))
			return
		}

		if !claims.CustomClaims.HasScope(scopeStr) {
			response.Status(http.StatusForbidden)
			if m.OnForbidden != nil {
				m.OnForbidden(response, request)
			}
			return
		}

		next(response, request)
	}
}
