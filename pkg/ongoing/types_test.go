package ongoing

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScoreStruct_Helpers(t *testing.T) {
	type scoreTest struct {
		name    string
		s       Score
		want    []byte
		notwant []byte
		isZero  bool
	}

	testcases := []scoreTest{
		{name: "empty score serializes as null",
			want:   []byte("null"),
			isZero: true,
		},
		{
			name: "severity_level:none included",
			s: Score{
				Source:        "garnet_test",
				SeverityLevel: "none",
			},
			want: []byte("\"severity_level\":\"none\""),
		},
		{
			name: "severity_level:none risk_score not included",
			s: Score{
				Source:        "garnet_test",
				SeverityLevel: "none",
			},
			notwant: []byte("risk_score"),
		},
		{
			name: "severity_level:'not_set' risk_score not included",
			s: Score{
				Source: "garnet_test",
			},
			notwant: []byte("risk_score"),
		},
		{
			name: "severity_level:high risk_score not set and not included",
			s: Score{
				Source:        "garnet_test",
				SeverityLevel: "high",
			},
			// risk_score must be explicitly calculated and set.
			notwant: []byte("risk_score"),
		},
		{
			name: "severity_level:critical risk_score included",
			s: Score{
				Source:        "garnet_test",
				SeverityLevel: "critical",
				RiskScore:     90,
			},
			want: []byte("\"risk_score\":90"),
		},
	}

	for i, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.isZero, test.s.IsZero(),
				"failed at IsZero() at index %d", i)
			data, err := test.s.MarshalJSON()
			require.NoError(t, err, "failed at index %d", i)
			if test.want != nil {
				require.Contains(t, string(data), string(test.want),
					"failed at require.Contains() index %d", i)
			}
			if test.notwant != nil {
				require.NotContains(t, string(data), string(test.notwant),
					"failed at require.NotContains() index %d", i)
			}
		})
	}
}
