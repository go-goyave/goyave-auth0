package auth0

import (
	"fmt"
	"testing"

	"github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/assert"
	"goyave.dev/goyave/v5/validation"
)

func TestConfig(t *testing.T) {
	t.Run("Default", func(t *testing.T) {
		want := Config{
			IssuerDomains: []string{},
			Audiences:     []string{},
			Algorithm:     validator.RS256,
			CacheTTL:      15 * 60,
			ClientID:      "",
			ClientSecret:  "",
		}
		assert.Equal(t, want, Config{}.Default())
	})
}

func TestSignatureAlgorithmValidator(t *testing.T) {
	t.Run("Constructor", func(t *testing.T) {
		v := SignatureAlgorithm()
		assert.NotNil(t, v)
		assert.Equal(t, "auth0_signature_algorithm", v.Name())
		assert.True(t, v.IsType())
		assert.False(t, v.IsTypeDependent())
		assert.Empty(t, v.MessagePlaceholders(&validation.Context{}))
	})

	cases := []struct {
		value     any
		wantValue any
		want      bool
	}{
		{value: 123, want: false},
		{value: "not_an_alg", want: true, wantValue: validator.SignatureAlgorithm("not_an_alg")}, // The validator itself will check that the value is correct on instantiation
		{value: validator.RS256, want: true, wantValue: validator.RS256},
		{value: string(validator.ES256), want: true, wantValue: validator.ES256},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("Validate_%v_%t", c.value, c.want), func(t *testing.T) {
			v := SignatureAlgorithm()
			ctx := &validation.Context{
				Value: c.value,
			}
			assert.Equal(t, c.want, v.Validate(ctx))
		})
	}
}
