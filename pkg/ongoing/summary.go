package ongoing

import "encoding/json"

// Process Ref.
//
// The canonical, deduplicated process entry.
// Keyed by the process hash (a process instance).
// The exe hash is the executable-level path identity.
// The ancestry is a flat chain of process refs, each of which is keyed by its own
// process hash. Ancestry entries are descriptive only; they do not carry their own
// ancestry (which would be recursive).

type ProcessRef struct {
	ProcessHash string       `json:"process_hash"` // Instance identity (== map key).
	ExeHash     string       `json:"exe_hash"`     // Executable identity.
	Pid         uint32       `json:"pid"`          // Process ID.
	Exe         string       `json:"exe"`          // Executable path.
	Args        string       `json:"args"`         // Arguments.
	Ancestry    []ProcessRef `json:"ancestry"`     // Flat ancestry chain.
}

func (p ProcessRef) Clone() ProcessRef {
	cloned := p
	cloned.Ancestry = nil
	if len(p.Ancestry) > 0 {
		cloned.Ancestry = make([]ProcessRef, len(p.Ancestry))
		for i, a := range p.Ancestry {
			cloned.Ancestry[i] = a.Clone()
		}
	}
	return cloned
}

func (p ProcessRef) IsZero() bool {
	return p.ProcessHash == "" &&
		p.ExeHash == "" &&
		p.Pid == 0 &&
		p.Exe == "" &&
		p.Args == "" &&
		len(p.Ancestry) == 0
}

func (p ProcessRef) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		ProcessHash string       `json:"process_hash,omitempty"`
		ExeHash     string       `json:"exe_hash,omitempty"`
		Pid         uint32       `json:"pid,omitempty"`
		Exe         string       `json:"exe,omitempty"`
		Args        string       `json:"args,omitempty"`
		Ancestry    []ProcessRef `json:"ancestry,omitempty"`
	}{
		ProcessHash: p.ProcessHash,
		ExeHash:     p.ExeHash,
		Pid:         p.Pid,
		Exe:         p.Exe,
		Args:        p.Args,
		Ancestry:    p.Ancestry,
	})
}

// Process Registry.
//
// The process table for the whole run, keyed by the canonical process
// hash string.

type ProcessRegistry map[string]ProcessRef

func (r ProcessRegistry) Clone() ProcessRegistry {
	if r == nil {
		return nil
	}
	cloned := make(ProcessRegistry, len(r))
	for k, v := range r {
		cloned[k] = v.Clone()
	}
	return cloned
}

func (r ProcessRegistry) IsZero() bool {
	return len(r) == 0
}

func (r ProcessRegistry) Get(key string) (ProcessRef, bool) {
	v, ok := r[key]
	return v, ok
}

func (r ProcessRegistry) MarshalJSON() ([]byte, error) {
	if r.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(map[string]ProcessRef(r))
}
