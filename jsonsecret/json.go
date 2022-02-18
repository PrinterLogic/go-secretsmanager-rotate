package jsonsecret

import (
	"encoding/json"
	"github.com/printerlogic/go-secretsmanager-rotate"
	"reflect"
)

// Parser returns a rotate.SecretParser that will unmarshal into structs returned by the backing factory function.
func Parser(target rotate.Secret) rotate.SecretParser {
	var ptr bool
	rt := reflect.TypeOf(target)
	if rt.Kind() == reflect.Ptr {
		ptr = true
		rt = rt.Elem()
	}
	return &parser{target: rt, asPtr: ptr}
}

type parser struct {
	// target is the pointer type for the rotate.Secret
	target reflect.Type
	asPtr  bool
}

func (p *parser) Parse(s rotate.Secret) (rotate.Secret, error) {
	data, err := s.Value()
	if err != nil {
		return s, err
	}

	target := reflect.New(p.target)
	err = json.Unmarshal(data, target.Interface())
	if !p.asPtr {
		return target.Elem().Interface().(rotate.Secret), err
	}
	return target.Interface().(rotate.Secret), err
}
