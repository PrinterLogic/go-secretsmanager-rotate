package rotate

import "fmt"

type Event struct {
	// SecretId contains the ARN of the secret this rotation lambda is managing
	SecretId string

	// ClientRequestToken is the version ID being managed by this rotation lambda
	ClientRequestToken string

	// Step is the phase of rotation that this rotation lambda is handling
	Step Step
}

const (
	// StepCreate is the first step of secret rotation
	// Create a new version of the secret. Secrets Manager labels the new version with the staging label `AWSPENDING`.
	StepCreate Step = "createSecret"

	// StepSet is the second step of secret rotation
	// Change the credentials in the database or service to match the new credentials in the `AWSPENDING` version.
	StepSet Step = "setSecret"

	// StepTest is the third step of secret rotation
	// Test the `AWSPENDING` version of the secret by using it to access the database or service.
	StepTest Step = "testSecret"

	// StepFinish is the fourth and final step of secret rotation
	// Moves the label `AWSCURRENT` from the previous secret version to this version. Secrets Manager adds the
	// `AWSPREVIOUS` staging label to the previous version, so that you retain the last known good version of the secret.
	StepFinish Step = "finishSecret"
)

// Step represents one of the four steps of secrets rotation
// More info on the different steps can be seen with the individual steps:
//	1) StepCreate
//	2) StepSet
//	3) StepTest
//	4) StepFinish
type Step string

func (r Step) MarshalText() ([]byte, error) {
	return []byte(r), nil
}

func (r *Step) UnmarshalText(text []byte) error {
	*r = Step(text)
	switch *r {
	case StepCreate, StepSet, StepTest, StepFinish:
		return nil
	default:
		return fmt.Errorf("unknown step: %s", text)
	}
}
