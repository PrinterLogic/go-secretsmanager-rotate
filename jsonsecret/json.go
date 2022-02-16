package jsonsecret

import (
	"encoding/json"
	"github.com/printerlogic/go-secretsmanager-rotate"
)

// Parser is a rotate.SecretParser that will unmarshal into structs returned by the backing factory function
// The backing factory function must return an instance value. The pointer will be used directly with the json.Unmarshaler
type Parser func() rotate.Secret

func (factory Parser) Parse(s rotate.Secret) (rotate.Secret, error) {
	data, err := s.Value()
	if err != nil {
		return s, err
	}

	target := factory()
	err = json.Unmarshal(data, &target)
	return target, nil
}

// This ensures that our Parser is a compliant rotate.SecretParser
func _(parser Parser) rotate.SecretParser {
	return parser
}
