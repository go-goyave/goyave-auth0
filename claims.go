package auth0

import (
	"net/http"

	"github.com/auth0/go-jwt-middleware/v3/validator"
	"goyave.dev/goyave/v5"
	"goyave.dev/goyave/v5/auth"
)

const MetaScope = "goyave.auth0.scope"

type Claims[T validator.CustomClaims] struct {
	RegisteredClaims validator.RegisteredClaims
	CustomClaims     T
}

type ScopeClaims interface {
	validator.CustomClaims
	HasScope(scope string) bool
}

type ScopeMiddleware[C ScopeClaims] struct {
	goyave.Component
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

		claims, ok := request.Extra[auth.ExtraJWTClaims{}].(*Claims[C])
		if !ok {
			next(response, request)
			return
		}

		if !claims.CustomClaims.HasScope(scopeStr) {
			// TODO option for custom forbidden handling (e.g. custom message instead of status handler)
			response.Status(http.StatusForbidden)
			return
		}

		next(response, request)
	}
}
