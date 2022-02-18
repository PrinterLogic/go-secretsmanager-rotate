package rotate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"log"
	"math/rand"
	"strconv"
	"testing"
	"time"
)

func TestRotator(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	t.Run("create event", func(t *testing.T) {
		t.Run("nominal service creates new secret", func(t *testing.T) {
			event := testEvent(StepCreate)

			currentValue := strconv.Itoa(rand.Int())
			currentOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    testVersionId(),
				SecretBinary: []byte(currentValue),
			}

			sm := &mockSecretsManager{
				Existing: map[string]*secretsmanager.GetSecretValueOutput{
					AWSCURRENT: currentOutput,
				},
			}

			newValue := strconv.Itoa(rand.Int())
			svc := &mockService{
				OnCreate: StringSecret(newValue),
			}
			assert.NoError(t, testRotator(t, sm, svc).Handle(context.TODO(), event))

			if !assertApiCounts(t, sm, apiCounts{Lookups: 1, Creates: 1}) || !assertServiceCounts(t, svc, serviceCounts{Creates: 1, Parses: 1}) {
				return
			}

			// ensure the secret provided to our service Create was interpreted as binary
			assert.IsType(t, BinarySecret{}, svc.CreateCalled[0], "expected SecretBinary to be parsed into BinarySecret")
			// Ensure our secret was sent to secrets manager correctly
			assert.Equal(t, event.SecretId, *sm.Creations[0].SecretId)
			assert.Equal(t, newValue, *sm.Creations[0].SecretString)
			assert.Equal(t, []string{AWSPENDING}, sm.Creations[0].VersionStages)
		})

		t.Run("when request token is already current version", func(t *testing.T) {
			event := testEvent(StepCreate)

			currentValue := strconv.Itoa(rand.Int())
			currentOutput := &secretsmanager.GetSecretValueOutput{
				// The requested token is already the current secret version
				VersionId:    &event.ClientRequestToken,
				SecretBinary: []byte(currentValue),
			}
			sm := &mockSecretsManager{
				Existing: map[string]*secretsmanager.GetSecretValueOutput{
					AWSCURRENT: currentOutput,
				},
			}

			svc := &mockService{}
			assert.NoError(t, testRotator(t, sm, svc).Handle(context.TODO(), event))

			// The service is not consulted because our requested token is the current version
			if !assertApiCounts(t, sm, apiCounts{Lookups: 1}) || !assertServiceCounts(t, svc, serviceCounts{Parses: 1}) {
				return
			}
		})
	})

	t.Run("set event", func(t *testing.T) {
		t.Run("nominal service sets updated secret", func(t *testing.T) {
			event := testEvent(StepSet)

			currentValue := strconv.Itoa(rand.Int())
			currentOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    testVersionId(),
				SecretBinary: []byte(currentValue),
			}

			pendingValue := strconv.Itoa(rand.Int())
			pendingOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    &event.ClientRequestToken,
				SecretString: &pendingValue,
			}

			sm := &mockSecretsManager{
				Existing: map[string]*secretsmanager.GetSecretValueOutput{
					AWSCURRENT: currentOutput,
					AWSPENDING: pendingOutput,
				},
			}
			svc := &mockService{}
			assert.NoError(t, testRotator(t, sm, svc).Handle(context.TODO(), event))

			if !assertApiCounts(t, sm, apiCounts{Lookups: 2}) || !assertServiceCounts(t, svc, serviceCounts{Parses: 2, Sets: 1}) {
				return
			}
		})

		t.Run("requested token is already current version id", func(t *testing.T) {
			event := testEvent(StepSet)

			currentValue := strconv.Itoa(rand.Int())
			currentOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    &event.ClientRequestToken,
				SecretBinary: []byte(currentValue),
			}

			pendingValue := strconv.Itoa(rand.Int())
			pendingOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    testVersionId(),
				SecretString: &pendingValue,
			}

			sm := &mockSecretsManager{
				Existing: map[string]*secretsmanager.GetSecretValueOutput{
					AWSCURRENT: currentOutput,
					AWSPENDING: pendingOutput,
				},
			}
			svc := &mockService{}
			assert.NoError(t, testRotator(t, sm, svc).Handle(context.TODO(), event))

			// service only parses the current secret because the requested token is already the current secret version
			if !assertApiCounts(t, sm, apiCounts{Lookups: 1}) || !assertServiceCounts(t, svc, serviceCounts{Parses: 1}) {
				return
			}
		})

		t.Run("requested token is not the pending version id", func(t *testing.T) {
			event := testEvent(StepSet)

			currentValue := strconv.Itoa(rand.Int())
			currentOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    testVersionId(),
				SecretBinary: []byte(currentValue),
			}

			pendingValue := strconv.Itoa(rand.Int())
			pendingOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    testVersionId(),
				SecretString: &pendingValue,
			}

			sm := &mockSecretsManager{
				Existing: map[string]*secretsmanager.GetSecretValueOutput{
					AWSCURRENT: currentOutput,
					AWSPENDING: pendingOutput,
				},
			}
			svc := &mockService{}
			assert.NoError(t, testRotator(t, sm, svc).Handle(context.TODO(), event))

			// service does not get called to set secret because the requested token is not the pending secret version
			if !assertApiCounts(t, sm, apiCounts{Lookups: 2}) || !assertServiceCounts(t, svc, serviceCounts{Parses: 2}) {
				return
			}
		})
	})

	t.Run("test event", func(t *testing.T) {
		t.Run("nominal service test", func(t *testing.T) {
			event := testEvent(StepTest)

			pendingValue := strconv.Itoa(rand.Int())
			pendingOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    &event.ClientRequestToken,
				SecretString: &pendingValue,
			}

			sm := &mockSecretsManager{
				Existing: map[string]*secretsmanager.GetSecretValueOutput{
					AWSPENDING: pendingOutput,
				},
			}
			svc := &mockService{}
			assert.NoError(t, testRotator(t, sm, svc).Handle(context.TODO(), event))

			if !assertApiCounts(t, sm, apiCounts{Lookups: 1}) || !assertServiceCounts(t, svc, serviceCounts{Parses: 1, Tests: 1}) {
				return
			}
			// Verify that pendingOutput.SecretString is being parsed into a StringSecret
			assert.IsType(t, StringSecret(""), svc.TestCalled[0])
		})

		t.Run("request token is not the pending version id", func(t *testing.T) {
			event := testEvent(StepTest)

			pendingValue := strconv.Itoa(rand.Int())
			pendingOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    testVersionId(),
				SecretString: &pendingValue,
			}

			sm := &mockSecretsManager{
				Existing: map[string]*secretsmanager.GetSecretValueOutput{
					AWSPENDING: pendingOutput,
				},
			}
			svc := &mockService{}
			assert.NoError(t, testRotator(t, sm, svc).Handle(context.TODO(), event))

			// service does not test secret because the requested token is not the pending version ID
			if !assertApiCounts(t, sm, apiCounts{Lookups: 1}) || !assertServiceCounts(t, svc, serviceCounts{Parses: 1}) {
				return
			}
		})
	})

	t.Run("finish event", func(t *testing.T) {
		t.Run("nominal service finish", func(t *testing.T) {
			event := testEvent(StepFinish)

			currentValue := strconv.Itoa(rand.Int())
			currentOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    testVersionId(),
				SecretString: &currentValue,
			}

			pendingValue := strconv.Itoa(rand.Int())
			pendingOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    &event.ClientRequestToken,
				SecretString: &pendingValue,
			}

			sm := &mockSecretsManager{
				Existing: map[string]*secretsmanager.GetSecretValueOutput{
					AWSCURRENT: currentOutput,
					AWSPENDING: pendingOutput,
				},
			}
			svc := &mockService{}
			assert.NoError(t, testRotator(t, sm, svc).Handle(context.TODO(), event))

			if !assertApiCounts(t, sm, apiCounts{Lookups: 2, Promotes: 1}) || !assertServiceCounts(t, svc, serviceCounts{Parses: 2, Finishes: 1}) {
				return
			}
			assert.Equal(t, *pendingOutput.VersionId, *sm.Promotions[0].MoveToVersionId)
			assert.Equal(t, *currentOutput.VersionId, *sm.Promotions[0].RemoveFromVersionId)
		})

		t.Run("request token is already the current version", func(t *testing.T) {
			event := testEvent(StepFinish)

			currentValue := strconv.Itoa(rand.Int())
			currentOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    &event.ClientRequestToken,
				SecretString: &currentValue,
			}

			pendingValue := strconv.Itoa(rand.Int())
			pendingOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    &event.ClientRequestToken,
				SecretString: &pendingValue,
			}

			sm := &mockSecretsManager{
				Existing: map[string]*secretsmanager.GetSecretValueOutput{
					AWSCURRENT: currentOutput,
					AWSPENDING: pendingOutput,
				},
			}
			svc := &mockService{}
			assert.NoError(t, testRotator(t, sm, svc).Handle(context.TODO(), event))

			// secret is not promoted because the request token is already the current version ID
			if !assertApiCounts(t, sm, apiCounts{Lookups: 1}) || !assertServiceCounts(t, svc, serviceCounts{Parses: 1}) {
				return
			}
		})

		t.Run("request token is not the pending version", func(t *testing.T) {
			event := testEvent(StepFinish)

			currentValue := strconv.Itoa(rand.Int())
			currentOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    testVersionId(),
				SecretString: &currentValue,
			}

			pendingValue := strconv.Itoa(rand.Int())
			pendingOutput := &secretsmanager.GetSecretValueOutput{
				VersionId:    testVersionId(),
				SecretString: &pendingValue,
			}

			sm := &mockSecretsManager{
				Existing: map[string]*secretsmanager.GetSecretValueOutput{
					AWSCURRENT: currentOutput,
					AWSPENDING: pendingOutput,
				},
			}
			svc := &mockService{}
			assert.NoError(t, testRotator(t, sm, svc).Handle(context.TODO(), event))

			// secret is not promoted when the request token is not the pending version id
			if !assertApiCounts(t, sm, apiCounts{Lookups: 2}) || !assertServiceCounts(t, svc, serviceCounts{Parses: 2}) {
				return
			}
		})
	})
}

type apiCounts struct {
	Lookups  int
	Creates  int
	Promotes int
}

func assertApiCounts(t *testing.T, m *mockSecretsManager, counts apiCounts) bool {
	return assert.Len(t, m.Lookups, counts.Lookups, "expected number of GetSecretValue() calls") &&
		assert.Len(t, m.Creations, counts.Creates, "expected number of PutSecretValue() calls") &&
		assert.Len(t, m.Promotions, counts.Promotes, "expected number of UpdateSecretVersionStage() calls")
}

type serviceCounts struct {
	Creates  int
	Sets     int
	Tests    int
	Finishes int
	Parses   int
}

func assertServiceCounts(t *testing.T, m *mockService, counts serviceCounts) bool {
	return assert.Len(t, m.CreateCalled, counts.Creates, "expected number of Service.Create() calls") &&
		assert.Len(t, m.SetCalled, counts.Sets, "expected number of Service.Set() calls") &&
		assert.Len(t, m.TestCalled, counts.Tests, "expected number of Service.Test() calls") &&
		assert.Len(t, m.FinishCalled, counts.Finishes, "expected number of Service.Finish() calls") &&
		assert.Len(t, m.ParseCalled, counts.Parses, "expected number of Service.Parse() calls")
}

func testRotator(t *testing.T, api SecretsManagerApi, service Service) Handler {
	logOutput := &bytes.Buffer{}
	t.Cleanup(func() {
		if logOutput.Len() > 0 {
			t.Log("Log output from rotator:\n" + logOutput.String())
		}
	})
	return &rotator{
		api:            api,
		service:        service,
		logger:         log.New(logOutput, "START-OF-LOG-MSG: ", 0),
		networkTimeout: time.Second,
	}
}

func testEvent(step Step) Event {
	return Event{
		SecretId:           fmt.Sprintf("secret-id-%d", rand.Uint32()),
		ClientRequestToken: fmt.Sprintf("request-token-%d", rand.Uint32()),
		Step:               step,
	}
}

func testVersionId() *string {
	versionId := fmt.Sprintf("existing-version-%d", rand.Uint32())
	return &versionId
}

type setSecretParams struct {
	Current Secret
	Pending Secret
}

type mockService struct {
	OnCreate     Secret
	CreateCalled []Secret
	SetCalled    []*setSecretParams
	TestCalled   []Secret
	FinishCalled []Secret
	ParseCalled  []Secret
}

func (m *mockService) Create(_ context.Context, current Secret) (Secret, error) {
	m.CreateCalled = append(m.CreateCalled, current)
	return m.OnCreate, nil
}

func (m *mockService) Set(_ context.Context, current Secret, pending Secret) error {
	m.SetCalled = append(m.SetCalled, &setSecretParams{
		Current: current,
		Pending: pending,
	})
	return nil
}

func (m *mockService) Test(_ context.Context, pending Secret) error {
	m.TestCalled = append(m.TestCalled, pending)
	return nil
}

func (m *mockService) Finish(_ context.Context, pending Secret) error {
	m.FinishCalled = append(m.FinishCalled, pending)
	return nil
}

func (m *mockService) Parse(secret Secret) (Secret, error) {
	m.ParseCalled = append(m.ParseCalled, secret)
	return secret, nil
}

type mockSecretsManager struct {
	Existing   map[string]*secretsmanager.GetSecretValueOutput
	Lookups    []*secretsmanager.GetSecretValueInput
	Creations  []*secretsmanager.PutSecretValueInput
	Promotions []*secretsmanager.UpdateSecretVersionStageInput
}

func (m *mockSecretsManager) GetSecretValue(_ context.Context, params *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	m.Lookups = append(m.Lookups, params)
	if m.Existing != nil {
		if output, ok := m.Existing[*params.VersionStage]; ok {
			return output, nil
		}
	}
	return nil, errors.New("mock: no output for stage configured: " + *params.VersionStage)
}

func (m *mockSecretsManager) PutSecretValue(_ context.Context, params *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	m.Creations = append(m.Creations, params)
	// for mocking purposes, we assume the error is exclusively checked and the output not used
	return nil, nil
}

func (m *mockSecretsManager) UpdateSecretVersionStage(_ context.Context, params *secretsmanager.UpdateSecretVersionStageInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretVersionStageOutput, error) {
	m.Promotions = append(m.Promotions, params)
	// for mocking purposes, we assume the error is exclusively checked and the output not used
	return nil, nil
}
