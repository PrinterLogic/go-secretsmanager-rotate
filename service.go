package rotate

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// Service is responsible for creating an updated secret value
type Service interface {
	Create(ctx context.Context, current Secret) (Secret, error)
}

// SettingService is a Service that wants to perform actions during the SET phase
type SettingService interface {
	Service
	Set(ctx context.Context, current Secret, pending Secret) error
}

// TestingService is a Service that wants to perform actions during the TEST phase
type TestingService interface {
	Service
	Test(ctx context.Context, pending Secret) error
}

// FinishingService is a Service that wants to perform actions during the FINISH phase
type FinishingService interface {
	Service
	Finish(ctx context.Context, pending Secret) error
}

// ParsingService is a Service that wants each Secret to pass through a SecretParser before actions are performed
type ParsingService interface {
	Service
	SecretParser
}

type Secret interface {
	// Binary indicates if the secret is binary or string format
	Binary() bool

	// Value returns the raw representation of the secret
	// If Binary() is false, the returned []byte can be safely converted to a string
	Value() ([]byte, error)
}

type StringSecret string

func (s StringSecret) Binary() bool {
	return false
}

func (s StringSecret) Value() ([]byte, error) {
	return []byte(s), nil
}

// Ensure that StringSecret remains Secret compatible
func _(s StringSecret) Secret {
	return s
}

type BinarySecret []byte

func (b BinarySecret) Binary() bool {
	return true
}

func (b BinarySecret) Value() ([]byte, error) {
	return b, nil
}

// Ensure that BinarySecret remains Secret compatible
func _(s BinarySecret) Secret {
	return s
}

func OutputAsSecret(secretValue *secretsmanager.GetSecretValueOutput) Secret {
	if secretValue.SecretString != nil {
		return StringSecret(*secretValue.SecretString)
	}
	return BinarySecret(secretValue.SecretBinary)
}

// SecretParser converts a Secret into an alternate representation of a Secret
type SecretParser interface {
	Parse(Secret) (Secret, error)
}
