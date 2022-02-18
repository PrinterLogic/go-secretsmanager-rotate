package jsonsecret_test

import (
	"github.com/printerlogic/go-secretsmanager-rotate"
	"github.com/printerlogic/go-secretsmanager-rotate/jsonsecret"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParser(t *testing.T) {
	t.Run("parses into pointer structs when provided a pointer type", func(t *testing.T) {
		// We seed our parser with a pointer of our desired secret type
		parser := jsonsecret.Parser(&SimpleSecret{})
		source := rotate.StringSecret(`{"username": "foo", "password": "bar"}`)

		secret, err := parser.Parse(source)
		assert.NoError(t, err)
		// We cast our returned secret to a pointer because we seeded a pointer of our secret type
		assert.Equal(t, "foo", secret.(*SimpleSecret).Username)
		assert.Equal(t, "bar", secret.(*SimpleSecret).Password)
	})

	t.Run("parses into value structs when provided a value type", func(t *testing.T) {
		// We seed our parser with a value of our desired secret type
		parser := jsonsecret.Parser(SimpleSecret{})
		source := rotate.StringSecret(`{"username": "purple", "password": "shoes"}`)

		secret, err := parser.Parse(source)
		assert.NoError(t, err)
		// We cast our returned secret to a value type because we seeded a value of our secret type
		assert.Equal(t, "purple", secret.(SimpleSecret).Username)
		assert.Equal(t, "shoes", secret.(SimpleSecret).Password)
	})
}

type SimpleSecret struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s SimpleSecret) Binary() bool {
	panic("not implement")
}

func (s SimpleSecret) Value() ([]byte, error) {
	panic("not implement")
}
