package auth0

import (
	"net/http"

	"goyave.dev/goyave/v5"
	"goyave.dev/goyave/v5/util/errors"
)

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
		scope, ok := request.Route.LookupMeta(MetaScope) // TODO limitation: only the last scope is applied, cannot require multiple scopes
		if !ok {
			next(response, request)
			return
		}
		scopeStr, _ := scope.(string) // TODO allow slice of strings (user needs to have all scopes)

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
