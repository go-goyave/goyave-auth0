package auth0

import (
	"reflect"

	"github.com/auth0/go-jwt-middleware/v3/validator"
	"goyave.dev/goyave/v5/config"
	"goyave.dev/goyave/v5/lang"
	v "goyave.dev/goyave/v5/validation"
)

// Config for the Auth0 [Authenticator].
type Config struct {
	Algorithm validator.SignatureAlgorithm // TODO type incompatible with v6 Config by default (need to create a validator for this). Not a problem for v5.

	// IssuerDomain of the issuer used to generate the issuer URL. (e.g.: "dev-abcdefg.eu.auth0.com")
	//
	// The issuer URL should match the `iss` claim in the JWT. Tokens with a
	// different issuer will be rejected.
	//
	// See [validator.WithIssuer] for more details.
	IssuerDomain string

	// Audiences expected audience claims (`aud`) for token validation.
	//
	// The token must contain at least one of the specified audiences. Tokens without
	// any matching audience will be rejected.
	//
	// See [validator.WithAudience] for more details.
	Audiences []string

	// CacheTTL the number of seconds for the JWT cache refresh interval.
	// See [jwks.WithCacheTTL] for more information.
	// Defaults to 15 minutes.
	CacheTTL int
}

// RuleSet returns the validation rules for this configuration section.
// Currently not used. Implemented for Goyave v6 forward compatibility.
func (Config) RuleSet() v.RuleSet {
	return v.RuleSet{
		{Path: v.CurrentElement, Rules: v.List{v.Required(), v.Object()}},
		{Path: "IssuerDomain", Rules: v.List{v.Required(), v.String(), v.Min(1)}},
		{Path: "Audiences", Rules: v.List{v.Required(), v.Array(), v.Min(1)}},
		{Path: "Audiences[]", Rules: v.List{v.String(), v.Min(1)}},
		{Path: "Algorithm", Rules: v.List{v.Required(), v.String(), SignatureAlgorithm()}},
	}
}

// Default returns the default configuration values.
// Currently not used. Implemented for Goyave v6 forward compatibility.
func (Config) Default() Config {
	return Config{
		IssuerDomain: "",
		Audiences:    []string{},
		Algorithm:    validator.HS256,
		CacheTTL:     15 * 60,
	}
}

func init() {
	// Goyave v5 config
	config.Register("auth.auth0.issuerDomain", config.Entry{Value: "", Type: reflect.String})
	config.Register("auth.auth0.audiences", config.Entry{Value: []string{}, Type: reflect.String, IsSlice: true})
	config.Register("auth.auth0.algorithm", config.Entry{Value: "", Type: reflect.String})
	config.Register("auth.auth0.cacheTTL", config.Entry{Value: 15 * 60, Type: reflect.Int})
}

// SignatureAlgorithmValidator converts the field under validation to the [validator.SignatureAlgorithm] string alias.
type SignatureAlgorithmValidator struct{ v.BaseValidator }

// Validate validates the given data. Set [v.Context.Value] to [validator.SignatureAlgorithm] if it passes.
func (v *SignatureAlgorithmValidator) Validate(ctx *v.Context) bool {
	str, ok := ctx.Value.(string)
	if !ok {
		return false
	}

	ctx.Value = validator.SignatureAlgorithm(str)
	return true
}

// Name returns the string name of the validator.
func (v *SignatureAlgorithmValidator) Name() string { return "auth0_signature_algorithm" }

// IsType returns true.
func (v *SignatureAlgorithmValidator) IsType() bool { return true }

// SignatureAlgorithm converts the field under validation to the [validator.SignatureAlgorithm] string alias.
// The actual value and if the algorithm is allowed or not is not checked by this validator. If an invalid
// value is given, it will be returned by [NewAuthenticator].
func SignatureAlgorithm() *SignatureAlgorithmValidator {
	return &SignatureAlgorithmValidator{}
}

func init() {
	lang.SetDefaultValidationRule("auth0_signature_algorithm", "The :field must be a valid signature algorithm name.")
	lang.SetDefaultValidationRule("auth0_signature_algorithm.element", "The :field elements must be valid signature algorithm names.")
}
