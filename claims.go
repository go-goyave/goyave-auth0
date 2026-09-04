package auth0

import (
	"context"

	"github.com/auth0/go-jwt-middleware/v3/validator"
)

// ExtraAuth0Claims key for request extra storing [Claims].
// Set by the [AppAuthenticator] and [Authenticator].
type ExtraAuth0Claims struct{}

// CustomClaims is a type constraint allowing reflection-less [validator.CustomClaims] pointer instantiation.
// Implementation should use a pointer receiver on the Validate method.
type CustomClaims[T any] interface {
	*T
	validator.CustomClaims
}

// Claims storing registered and custom JWT claims.
type Claims[T validator.CustomClaims] struct {
	RegisteredClaims validator.RegisteredClaims
	CustomClaims     T
}

// NoCustomClaims represents empty custom JWT claims.
// Use it when your tokens don't contain any custom claim and when
// registered claims are sufficient.
type NoCustomClaims struct{}

func (*NoCustomClaims) Validate(_ context.Context) error {
	return nil
}
