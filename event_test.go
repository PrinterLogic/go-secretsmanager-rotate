package rotate

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStep(t *testing.T) {
	t.Run("json.Marshal() encodes step into plain string", func(t *testing.T) {
		container := withStep{Step: StepFinish}
		raw, err := json.Marshal(&container)
		assert.NoError(t, err)
		assert.JSONEq(t, `{"step":"finishSecret"}`, string(raw))
	})

	t.Run("json.Unmarshal() works for valid step", func(t *testing.T) {
		cases := []struct {
			raw      string
			expected Step
		}{
			{`{"step": "createSecret"}`, StepCreate},
			{`{"step": "setSecret"}`, StepSet},
			{`{"step": "testSecret"}`, StepTest},
			{`{"step": "finishSecret"}`, StepFinish},
		}

		for _, c := range cases {
			t.Run(string(c.expected), func(t *testing.T) {
				var container withStep
				assert.NoError(t, json.Unmarshal([]byte(c.raw), &container))
				assert.Equal(t, c.expected, container.Step)
			})
		}
	})

	t.Run("json.Unmarshal() fails for unknown step value", func(t *testing.T) {
		raw := []byte(`{"step": "lkjasdhflkajsdf"}`)

		var container withStep
		assert.Error(t, json.Unmarshal(raw, &container))
	})
}

type withStep struct {
	Step Step `json:"step"`
}
