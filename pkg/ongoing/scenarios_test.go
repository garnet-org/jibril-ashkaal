package ongoing

import (
	"encoding/json"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/google/go-cmp/cmp"
)

func ptrUint32(v uint32) *uint32 {
	return &v
}

func TestScenarioGitHub_JobIndex_IsZero(t *testing.T) {
	assert.True(t, ScenarioGitHub{}.IsZero())
	assert.True(t, ScenarioGitHub{JobIndex: nil}.IsZero())

	assert.False(t, ScenarioGitHub{JobIndex: ptrUint32(0)}.IsZero())
	assert.False(t, ScenarioGitHub{JobIndex: ptrUint32(7)}.IsZero())
}

func TestScenarioGitHub_JobIndex_MarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		jobIndex    *uint32
		wantPresent bool
		wantValue   string
	}{
		{name: "unset omits key", jobIndex: nil, wantPresent: false},
		{name: "zero value emitted", jobIndex: ptrUint32(0), wantPresent: true, wantValue: `"job_index":0`},
		{name: "matrix max emitted", jobIndex: ptrUint32(255), wantPresent: true, wantValue: `"job_index":255`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Keep another field set so IsZero is false and the
			// scenario marshals to an object rather than null.
			s := ScenarioGitHub{Job: "build", JobIndex: tc.jobIndex}
			b, err := json.Marshal(s)
			assert.NoError(t, err)

			if tc.wantPresent {
				assert.Contains(t, string(b), tc.wantValue)
			} else {
				assert.NotContains(t, string(b), "job_index")
			}
		})
	}
}

func TestScenarioGitHub_JobIndex_RoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		jobIndex *uint32
	}{
		{name: "unset", jobIndex: nil},
		{name: "zero", jobIndex: ptrUint32(0)},
		{name: "non-zero", jobIndex: ptrUint32(255)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := ScenarioGitHub{
				ScenarioType: ScenarioTypeGitHub,
				Job:          "build",
				JobIndex:     tc.jobIndex,
			}
			b, err := json.Marshal(want)
			assert.NoError(t, err)

			var got ScenarioGitHub
			err = json.Unmarshal(b, &got)
			assert.NoError(t, err)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("scenario mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestScenarioGitHub_JobIndex_Clone(t *testing.T) {
	orig := ScenarioGitHub{Job: "build", JobIndex: ptrUint32(3)}
	clone, ok := orig.Clone().(ScenarioGitHub)
	assert.True(t, ok)

	// The clone must hold its own pointer, not alias the original.
	assert.NotZero(t, clone.JobIndex)
	assert.Equal(t, uint32(3), *clone.JobIndex)
	if clone.JobIndex == orig.JobIndex {
		t.Fatal("clone aliases the original JobIndex pointer")
	}

	// Mutating the clone's value must not affect the original.
	*clone.JobIndex = 9
	assert.Equal(t, uint32(3), *orig.JobIndex)

	// A nil JobIndex clones to nil.
	nilClone, ok := ScenarioGitHub{Job: "build"}.Clone().(ScenarioGitHub)
	assert.True(t, ok)
	assert.Zero(t, nilClone.JobIndex)
}

func TestScenarioGitHub_JobIndex_MarshalJSONMap(t *testing.T) {
	m, err := ScenarioGitHub{Job: "build"}.MarshalJSONMap()
	assert.NoError(t, err)
	_, ok := m["job_index"]
	assert.False(t, ok)

	m, err = ScenarioGitHub{Job: "build", JobIndex: ptrUint32(0)}.MarshalJSONMap()
	assert.NoError(t, err)
	v, ok := m["job_index"].(uint32)
	assert.True(t, ok)
	assert.Equal(t, uint32(0), v)
}
