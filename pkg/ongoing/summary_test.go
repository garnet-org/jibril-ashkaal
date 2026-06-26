package ongoing

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProcessRefIsZero(t *testing.T) {
	tests := []struct {
		name string
		ref  ProcessRef
		want bool
	}{
		{"empty", ProcessRef{}, true},
		{"hash only", ProcessRef{ProcessHash: "009af2c1"}, false},
		{"pid only", ProcessRef{Pid: 42}, false},
		{"args only", ProcessRef{Args: "--once"}, false},
		{"ancestry only", ProcessRef{Ancestry: []ProcessRef{{Exe: "/bin/sh"}}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ref.IsZero(); got != tt.want {
				t.Fatalf("IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessRefCloneIsDeep(t *testing.T) {
	original := ProcessRef{
		ProcessHash: "009af2c1",
		Exe:         "/usr/bin/curl",
		Ancestry: []ProcessRef{
			{Exe: "/usr/bin/bash"},
			{Exe: "/usr/bin/runner"},
		},
	}

	cloned := original.Clone()
	cloned.Ancestry[0].Exe = "/changed"

	if original.Ancestry[0].Exe != "/usr/bin/bash" {
		t.Fatalf("clone shares ancestry backing: original mutated to %q",
			original.Ancestry[0].Exe)
	}
}

func TestProcessRefMarshalJSON(t *testing.T) {
	if got, _ := json.Marshal(ProcessRef{}); string(got) != "null" {
		t.Fatalf("zero ProcessRef = %s, want null", got)
	}

	ref := ProcessRef{
		ProcessHash: "009af2c1",
		ExeHash:     "0012ab34",
		Pid:         42,
		Exe:         "/usr/bin/curl",
		Args:        "--silent",
		Ancestry:    []ProcessRef{{Exe: "/usr/bin/bash"}},
	}

	got, err := json.Marshal(ref)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	for _, want := range []string{`"process_hash":"009af2c1"`, `"pid":42`,
		`"args":"--silent"`, `"ancestry":[`, `"exe":"/usr/bin/bash"`} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("marshal = %s, missing %s", got, want)
		}
	}

	// Round-trip back into a ProcessRef.
	var back ProcessRef
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.ProcessHash != ref.ProcessHash || len(back.Ancestry) != 1 ||
		back.Ancestry[0].Exe != "/usr/bin/bash" {
		t.Fatalf("round-trip mismatch: %+v", back)
	}
}

func TestProcessRegistry(t *testing.T) {
	var empty ProcessRegistry
	if !empty.IsZero() {
		t.Fatal("nil registry should be zero")
	}
	if got, _ := json.Marshal(empty); string(got) != "null" {
		t.Fatalf("empty registry = %s, want null", got)
	}

	reg := ProcessRegistry{
		"009af2c1": {ProcessHash: "009af2c1", Exe: "/usr/bin/curl"},
		"0012ab34": {ProcessHash: "0012ab34", Exe: "/usr/bin/bash"},
	}

	if _, ok := reg.Get("009af2c1"); !ok {
		t.Fatal("Get miss for present key")
	}
	if _, ok := reg.Get("missing"); ok {
		t.Fatal("Get hit for absent key")
	}

	got, err := json.Marshal(reg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Keys are sorted by the standard library, so output is deterministic.
	if strings.Index(string(got), "0012ab34") > strings.Index(string(got), "009af2c1") {
		t.Fatalf("registry keys not in sorted order: %s", got)
	}

	cloned := reg.Clone()
	cloned["009af2c1"] = ProcessRef{ProcessHash: "009af2c1", Exe: "/changed"}
	if reg["009af2c1"].Exe != "/usr/bin/curl" {
		t.Fatalf("clone shares backing: original mutated to %q", reg["009af2c1"].Exe)
	}
}
