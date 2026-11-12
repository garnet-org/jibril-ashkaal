package ongoing

import (
	"encoding/json"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestCaptureTelemetryRoundTrip(t *testing.T) {
	for _, capture := range []string{
		`{"events_lost":0,"events_dropped":0,"drain_discarded":0,"attach_failures":0,"ready_before_workload":true}`,
		`{}`, `{"events_lost":1}`, `{"events_lost":-1}`, `{"events_lost":1.5}`,
		`{"events_lost":"0"}`, `{"events_lost":null}`, `{"ready_before_workload":false}`,
		`{"ready_before_workload":"true"}`, `[]`, `"invalid"`, `42`,
	} {
		t.Run(capture, func(t *testing.T) {
			var profile Profile
			assert.NoError(t, json.Unmarshal([]byte(`{"telemetry":{"capture":`+capture+`}}`), &profile))
			cloned := profile.Clone()
			assert.NotZero(t, cloned.Telemetry.Capture)
			encoded, err := json.Marshal(cloned)
			assert.NoError(t, err)
			var roundTrip struct {
				Telemetry struct {
					Capture json.RawMessage `json:"capture"`
				} `json:"telemetry"`
			}
			assert.NoError(t, json.Unmarshal(encoded, &roundTrip))
			var expected, actual any
			assert.NoError(t, json.Unmarshal([]byte(capture), &expected))
			assert.NoError(t, json.Unmarshal(roundTrip.Telemetry.Capture, &actual))
			assert.Equal(t, expected, actual)
			var decoded Profile
			assert.NoError(t, json.Unmarshal(encoded, &decoded))
			assert.Equal(t, cloned.Telemetry.Capture, decoded.Telemetry.Capture)
		})
	}
	var profile Profile
	assert.NoError(t, json.Unmarshal([]byte(`{}`), &profile))
	assert.Zero(t, profile.Telemetry.Capture)
	encoded, err := json.Marshal(profile.Clone())
	assert.NoError(t, err)
	assert.NotContains(t, string(encoded), `"capture"`)
	var full Profile
	assert.NoError(t, json.Unmarshal([]byte(`{"telemetry":{"capture":{"events_lost":0,"ready_before_workload":true}}}`), &full))
	cloned := full.Clone()
	*cloned.Telemetry.Capture.EventsLost = 1
	*cloned.Telemetry.Capture.ReadyBeforeWorkload = false
	assert.Equal(t, int64(0), *full.Telemetry.Capture.EventsLost)
	assert.Equal(t, true, *full.Telemetry.Capture.ReadyBeforeWorkload)
}
