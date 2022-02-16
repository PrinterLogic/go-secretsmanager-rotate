package rotate

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"log"
	"os"
	"time"
)

type Handler interface {
	Handle(context.Context, Event) error
}

type Config struct {
	SecretsManagerClient *secretsmanager.Client
	SecretService        Service
	Timeout              time.Duration
}

func New(c Config) Handler {
	if c.Timeout <= 0 {
		c.Timeout = time.Second
	}
	return &rotator{
		client:         c.SecretsManagerClient,
		service:        c.SecretService,
		logger:         log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile),
		networkTimeout: c.Timeout,
	}
}

type rotator struct {
	client         *secretsmanager.Client
	service        Service
	logger         *log.Logger
	networkTimeout time.Duration
}

func (r *rotator) Handle(ctx context.Context, event Event) error {
	defer r.logPrefixf("[%s]", event.Step)()
	r.logger.Println("Evaluating rotation for secret: %s and version: %s", event.SecretId, event.ClientRequestToken)

	switch event.Step {
	case StepCreate:
		return r.create(ctx, event)
	case StepSet:
		return r.set(ctx, event)
	case StepTest:
		return r.test(ctx, event)
	case StepFinish:
		return r.finish(ctx, event)
	}
	return fmt.Errorf("unknown rotate step: %s", event.Step)
}

func (r *rotator) logPrefixf(format string, params ...interface{}) func() {
	current := r.logger.Prefix()
	r.logger.SetPrefix(current + fmt.Sprintf(format, params...))
	return func() {
		r.logger.SetPrefix(current)
	}
}

func (r *rotator) create(ctx context.Context, event Event) error {
	currentVersion, current, err := r.secretByStage(ctx, event.SecretId, AWSCURRENT)
	if err != nil {
		return err
	}

	if currentVersion == event.ClientRequestToken {
		r.logger.Println(AWSCURRENT + " is already set to " + event.ClientRequestToken)
		return nil
	}

	pendingSecret, err := r.service.Create(ctx, current)
	if err != nil {
		return err
	}

	return r.putPendingSecret(ctx, event, pendingSecret)
}

func (r *rotator) set(ctx context.Context, event Event) error {
	setter, ok := r.service.(SettingService)
	if !ok {
		r.logger.Println("Service does not want to intercept SET actions")
		return nil
	}

	currentVersion, current, err := r.secretByStage(ctx, event.SecretId, AWSCURRENT)
	if err != nil {
		return err
	}

	if currentVersion == event.ClientRequestToken {
		r.logger.Println(AWSCURRENT + " is already set to " + event.ClientRequestToken)
		return nil
	}

	pendingVersion, pending, err := r.secretByStage(ctx, event.SecretId, AWSPENDING)
	if err != nil {
		return err
	}

	if pendingVersion != event.ClientRequestToken {
		r.logger.Println(AWSPENDING + " is not currently set to " + event.ClientRequestToken)
		return nil
	}

	return setter.Set(ctx, current, pending)
}

func (r *rotator) test(ctx context.Context, event Event) error {
	tester, ok := r.service.(TestingService)
	if !ok {
		r.logger.Println("Service does not want to intercept TEST actions")
		return nil
	}

	pendingVersion, pending, err := r.secretByStage(ctx, event.SecretId, AWSPENDING)
	if err != nil {
		return err
	}

	if pendingVersion != event.ClientRequestToken {
		r.logger.Println(AWSPENDING + " is not currently set to " + event.ClientRequestToken)
		return nil
	}

	return tester.Test(ctx, pending)
}

func (r *rotator) finish(ctx context.Context, event Event) error {
	err := func() error {
		finisher, ok := r.service.(FinishingService)
		if !ok {
			r.logger.Println("Service does not want to intercept FINISH actions")
			return nil
		}

		pendingVersion, pending, err := r.secretByStage(ctx, event.SecretId, AWSPENDING)
		if err != nil {
			return err
		}

		if pendingVersion != event.ClientRequestToken {
			r.logger.Println(AWSPENDING + " is not currently set to " + event.ClientRequestToken)
			return nil
		}

		return finisher.Finish(ctx, pending)
	}()
	if err != nil {
		return err
	}

	return r.setCurrentSecret(ctx, event)
}

const (
	AWSCURRENT = "AWSCURRENT"
	AWSPENDING = "AWSPENDING"
)

func (r *rotator) secretByStage(ctx context.Context, secretId string, stage string) (string, Secret, error) {
	ctx, cancel := r.network(ctx)
	defer cancel()

	output, err := r.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId:     &secretId,
		VersionStage: &stage,
	})
	if err != nil {
		return "", BinarySecret{}, err
	}

	secret, err := r.prepareSecret(output)
	return *output.VersionId, secret, err
}

func (r *rotator) putPendingSecret(ctx context.Context, event Event, value Secret) error {
	ctx, cancel := r.network(ctx)
	defer cancel()

	input := &secretsmanager.PutSecretValueInput{
		SecretId:           &event.SecretId,
		ClientRequestToken: &event.ClientRequestToken,
		VersionStages:      []string{AWSPENDING},
	}

	val, err := value.Value()
	if err != nil {
		return err
	}
	if value.Binary() {
		input.SecretBinary = val
	} else {
		str := string(val)
		input.SecretString = &str
	}

	_, err = r.client.PutSecretValue(ctx, input)
	return err
}

func (r *rotator) setCurrentSecret(ctx context.Context, event Event) error {
	currentVersion, _, err := r.secretByStage(ctx, event.SecretId, AWSCURRENT)
	if err != nil {
		return err
	}

	ctx, cancel := r.network(ctx)
	defer cancel()

	stage := AWSCURRENT
	_, err = r.client.UpdateSecretVersionStage(ctx, &secretsmanager.UpdateSecretVersionStageInput{
		SecretId:            &event.SecretId,
		VersionStage:        &stage,
		MoveToVersionId:     &event.ClientRequestToken,
		RemoveFromVersionId: &currentVersion,
	})
	return err
}

func (r *rotator) network(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, r.networkTimeout)
}

func (r *rotator) prepareSecret(secretValue *secretsmanager.GetSecretValueOutput) (secret Secret, err error) {
	secret = OutputAsSecret(secretValue)
	if parser, ok := r.service.(ParsingService); ok {
		secret, err = parser.Parse(secret)
	}
	return
}
