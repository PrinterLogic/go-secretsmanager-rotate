package rotate

import (
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"strconv"
	"testing"
	"time"
)

func TestOutputAsSecret(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	t.Run("for SecretString value", func(t *testing.T) {
		value := strconv.Itoa(rand.Int())
		output := &secretsmanager.GetSecretValueOutput{SecretString: &value}
		assert.IsType(t, StringSecret(""), OutputAsSecret(output), "expected SecretString value to be parsed into a StringSecret")
	})

	t.Run("for SecretBinary value", func(t *testing.T) {
		value := []byte(strconv.Itoa(rand.Int()))
		output := &secretsmanager.GetSecretValueOutput{SecretBinary: value}
		assert.IsType(t, BinarySecret{}, OutputAsSecret(output), "expected SecretBinary value to be parsed into a BinarySecret")
	})
}
