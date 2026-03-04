package ongoing

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// All detection events have these fields.

type Base struct {
	UUID       string     `json:"uuid"`       // The unique ID of the event.
	Timestamp  time.Time  `json:"timestamp"`  // The timestamp of the event.
	Note       string     `json:"note"`       // A note about the event.
	Metadata   Metadata   `json:"metadata"`   // The event metadata.
	Attenuator Attenuator `json:"attenuator"` // The attenuator of the event.
	Score      Score      `json:"score"`      // Event Security Risk Score.
	Background Background `json:"background"` // The event context.
	Scenarios  Scenarios  `json:"scenarios"`  // GitHub, Kubernetes, Host, etc.
}

// NOTE: Multiple events with the same UUID are typically treated as the same event, but
// with increasingly complete context. Keeping only the most recent event is a reasonable
// approach. However, if possible, merging the context of all such events is ideal.

func (b Base) Clone() Base {
	return Base{
		UUID:       b.UUID,
		Timestamp:  b.Timestamp,
		Note:       b.Note,
		Metadata:   b.Metadata.Clone(),
		Attenuator: b.Attenuator.Clone(),
		Score:      b.Score.Clone(),
		Background: b.Background.Clone(),
		Scenarios:  b.Scenarios.Clone(),
	}
}

func (b Base) IsZero() bool {
	return b.UUID == "" &&
		b.Timestamp.IsZero() &&
		b.Note == "" &&
		b.Metadata.IsZero() &&
		b.Attenuator.IsZero() &&
		b.Score.IsZero() &&
		b.Background.IsZero() &&
		b.Scenarios.IsZero()
}

func (b Base) MarshalJSON() ([]byte, error) {
	if b.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		UUID       string      `json:"uuid"`
		Timestamp  time.Time   `json:"timestamp"`
		Note       string      `json:"note,omitempty"`
		Metadata   *Metadata   `json:"metadata,omitempty"`
		Attenuator *Attenuator `json:"attenuator,omitempty"`
		Score      *Score      `json:"score,omitempty"`
		Background *Background `json:"background,omitempty"`
		Scenarios  *Scenarios  `json:"scenarios,omitempty"`
	}{
		UUID:      b.UUID,
		Timestamp: b.Timestamp,
		Note:      b.Note,
	}

	if !b.Metadata.IsZero() {
		created.Metadata = &b.Metadata
	}
	if !b.Attenuator.IsZero() {
		created.Attenuator = &b.Attenuator
	}
	if !b.Score.IsZero() {
		created.Score = &b.Score
	}
	if !b.Background.IsZero() {
		created.Background = &b.Background
	}
	if !b.Scenarios.IsZero() {
		created.Scenarios = &b.Scenarios
	}

	return json.Marshal(created)
}

func (b Base) MarshalJSONMap() (map[string]any, error) {
	if b.IsZero() {
		return nil, nil
	}

	result := make(map[string]any)

	// Always included fields.
	result["uuid"] = b.UUID
	result["timestamp"] = b.Timestamp

	// Omit empty fields.
	if b.Note != "" {
		result["note"] = b.Note
	}
	if !b.Metadata.IsZero() {
		result["metadata"] = b.Metadata
	}
	if !b.Attenuator.IsZero() {
		result["attenuator"] = b.Attenuator
	}
	if !b.Score.IsZero() {
		result["score"] = b.Score
	}
	if !b.Background.IsZero() {
		result["background"] = b.Background
	}
	if !b.Scenarios.IsZero() {
		scenariosMap, err := b.Scenarios.MarshalJSONMap()
		if err != nil {
			return nil, err
		}
		if scenariosMap != nil {
			result["scenarios"] = scenariosMap
		}
	}

	return result, nil
}

// Detection Event Metadata.

type Metadata struct {
	Kind          string `json:"kind"`          // Detection event class name.
	Name          string `json:"name"`          // Detection recipe name.
	Format        string `json:"format"`        // Detection event format.
	Version       string `json:"version"`       // Detection event format version.
	Description   string `json:"description"`   // Detection event description.
	Tactic        string `json:"tactic"`        // Detection event MITRE tactic.
	Technique     string `json:"technique"`     // Detection event MITRE technique.
	SubTechnique  string `json:"subtechnique"`  // Detection event MITRE subtechnique.
	Importance    string `json:"importance"`    // Detection event importance.
	Documentation string `json:"documentation"` // Detection event documentation.
}

func (m Metadata) Clone() Metadata {
	return Metadata{
		Kind:          m.Kind,
		Name:          m.Name,
		Format:        m.Format,
		Version:       m.Version,
		Description:   m.Description,
		Tactic:        m.Tactic,
		Technique:     m.Technique,
		SubTechnique:  m.SubTechnique,
		Importance:    m.Importance,
		Documentation: m.Documentation,
	}
}

func (m Metadata) IsZero() bool {
	return m.Kind == "" &&
		m.Name == "" &&
		m.Format == "" &&
		m.Version == "" &&
		m.Description == "" &&
		m.Tactic == "" &&
		m.Technique == "" &&
		m.SubTechnique == "" &&
		m.Importance == "" &&
		m.Documentation == ""
}

func (m Metadata) MarshalJSON() ([]byte, error) {
	if m.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Kind          string `json:"kind"`
		Name          string `json:"name"`
		Format        string `json:"format"`
		Version       string `json:"version"`
		Description   string `json:"description,omitempty"`
		Tactic        string `json:"tactic,omitempty"`
		Technique     string `json:"technique,omitempty"`
		SubTechnique  string `json:"subtechnique,omitempty"`
		Importance    string `json:"importance,omitempty"`
		Documentation string `json:"documentation,omitempty"`
	}{
		Kind:          m.Kind,
		Name:          m.Name,
		Format:        m.Format,
		Version:       m.Version,
		Description:   m.Description,
		Tactic:        m.Tactic,
		Technique:     m.Technique,
		SubTechnique:  m.SubTechnique,
		Importance:    m.Importance,
		Documentation: m.Documentation,
	})
}

// Security Risk Score.

type Score struct {
	Source        string   `json:"source"`         // Source of the score.
	Severity      int      `json:"severity"`       // Severity number of the detection (0-100).
	SeverityLevel string   `json:"severity_level"` // Severity level of the detection (none, low, medium, high, critical).
	Confidence    float64  `json:"confidence"`     // Confidence percentage of the detection (0.0-1.0).
	RiskScore     float64  `json:"risk_score"`     // Calculated and rounded up risk score of the detection (0.0-100.0).
	Reasons       []string `json:"reasons"`        // Reasons to explain to users why this score.
}

func (s Score) Clone() Score {
	return Score{
		Source:        s.Source,
		Severity:      s.Severity,
		SeverityLevel: s.SeverityLevel,
		Confidence:    s.Confidence,
		RiskScore:     s.RiskScore,
		Reasons:       append([]string(nil), s.Reasons...),
	}
}

func (s Score) IsZero() bool {
	return s.Source == "" &&
		s.Severity == 0 &&
		s.SeverityLevel == "" &&
		s.Confidence == 0 &&
		s.RiskScore == 0 &&
		len(s.Reasons) == 0
}

func (s Score) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Source        string   `json:"source"`
		Severity      int      `json:"severity"`
		SeverityLevel string   `json:"severity_level"`
		Confidence    float64  `json:"confidence"`
		RiskScore     float64  `json:"risk_score,omitempty"`
		Reasons       []string `json:"reasons,omitempty"`
	}{
		Source:        s.Source,
		Severity:      s.Severity,
		SeverityLevel: s.SeverityLevel,
		Confidence:    s.Confidence,
		RiskScore:     s.RiskScore,
		Reasons:       s.Reasons,
	})
}

// Attenuator.

type Attenuator struct {
	AttenuatedBy     string  `json:"attenuated_by"`      // The model that attenuated the detection.
	Interpretation   string  `json:"interpretation"`     // The interpretation of the attenuation.
	Thinking         string  `json:"thinking"`           // The thinking of the attenuation.
	IsFalsePositive  bool    `json:"is_false_positive"`  // Whether the detection is a false positive.
	NewSeverity      int     `json:"new_severity"`       // The new detection severity after attenuation (0-100).
	NewSeverityLevel string  `json:"new_severity_level"` // The new detection severity level after attenuation (low, medium, high, critical).
	NewConfidence    float64 `json:"new_confidence"`     // The new detection confidence after attenuation (0.0-1.0).
	NewRiskScore     float64 `json:"new_risk_score"`     // The new detection risk score after attenuation (0.0-100.0).
}

func (a Attenuator) Clone() Attenuator {
	return Attenuator{
		AttenuatedBy:     a.AttenuatedBy,
		Interpretation:   a.Interpretation,
		Thinking:         a.Thinking,
		IsFalsePositive:  a.IsFalsePositive,
		NewSeverity:      a.NewSeverity,
		NewSeverityLevel: a.NewSeverityLevel,
		NewConfidence:    a.NewConfidence,
		NewRiskScore:     a.NewRiskScore,
	}
}

func (a Attenuator) IsZero() bool {
	return a.AttenuatedBy == "" &&
		a.Interpretation == "" &&
		a.Thinking == "" &&
		!a.IsFalsePositive &&
		a.NewSeverity == 0 &&
		a.NewSeverityLevel == "" &&
		a.NewConfidence == 0 &&
		a.NewRiskScore == 0
}

func (a Attenuator) MarshalJSON() ([]byte, error) {
	if a.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		AttenuatedBy     string  `json:"attenuated_by"`
		Interpretation   string  `json:"interpretation"`
		Thinking         string  `json:"thinking,omitempty"`
		IsFalsePositive  bool    `json:"is_false_positive"`
		NewSeverity      int     `json:"new_severity"`
		NewSeverityLevel string  `json:"new_severity_level"`
		NewConfidence    float64 `json:"new_confidence"`
		NewRiskScore     float64 `json:"new_risk_score"`
	}{
		AttenuatedBy:     a.AttenuatedBy,
		Interpretation:   a.Interpretation,
		Thinking:         a.Thinking,
		IsFalsePositive:  a.IsFalsePositive,
		NewSeverity:      a.NewSeverity,
		NewSeverityLevel: a.NewSeverityLevel,
		NewConfidence:    a.NewConfidence,
		NewRiskScore:     a.NewRiskScore,
	})
}

// Context.

type Background struct {
	Containers  Containers    `json:"containers"`
	Files       []File        `json:"file_list"`
	Flows       []Flow        `json:"flow_list"`
	Ancestry    []Process     `json:"ancestry"`
	LegacyFiles FileAggregate `json:"files"` // TODO: Remove this field.
	LegacyFlows FlowAggregate `json:"flows"` // TODO: Remove this field.
}

func (b Background) Clone() Background {
	ancestry := make([]Process, len(b.Ancestry))
	copy(ancestry, b.Ancestry)
	files := make([]File, len(b.Files))
	copy(files, b.Files)
	flows := make([]Flow, len(b.Flows))
	copy(flows, b.Flows)
	return Background{
		Containers:  b.Containers.Clone(),
		Files:       files,
		Flows:       flows,
		Ancestry:    ancestry,
		LegacyFiles: b.LegacyFiles.Clone(),
		LegacyFlows: b.LegacyFlows.Clone(),
	}
}

func (b Background) IsZero() bool {
	return b.Containers.IsZero() &&
		len(b.Files) == 0 &&
		len(b.Flows) == 0 &&
		len(b.Ancestry) == 0 &&
		b.LegacyFiles.IsZero() &&
		b.LegacyFlows.IsZero()
}

func (b Background) MarshalJSON() ([]byte, error) {
	if b.IsZero() {
		return []byte("null"), nil
	}

	hasNewFiles := len(b.Files) > 0
	hasNewFlows := len(b.Flows) > 0
	hasLegacyFiles := !b.LegacyFiles.IsZero()
	hasLegacyFlows := !b.LegacyFlows.IsZero()

	created := struct {
		Containers  *Containers    `json:"containers,omitempty"`
		Files       []File         `json:"file_list,omitempty"`
		Flows       []Flow         `json:"flow_list,omitempty"`
		Ancestry    []Process      `json:"ancestry,omitempty"`
		LegacyFiles *FileAggregate `json:"files,omitempty"`
		LegacyFlows *FlowAggregate `json:"flows,omitempty"`
	}{
		Ancestry: b.Ancestry,
	}

	// Only makes sense to include the full type if sub-type is not empty.
	if !b.Containers.IsZero() && len(b.Containers.Containers) > 0 {
		created.Containers = &b.Containers
	}

	if hasNewFiles {
		created.Files = b.Files
	} else if hasLegacyFiles {
		created.LegacyFiles = &b.LegacyFiles
	}

	if hasNewFlows {
		created.Flows = b.Flows
	} else if hasLegacyFlows {
		created.LegacyFlows = &b.LegacyFlows
	}

	return json.Marshal(created)
}

// File Access Detection Event.

type FileAccess struct {
	Base
	File    File    `json:"file"`    // File accessed by the process.
	Process Process `json:"process"` // Process that accessed the file.
}

func (f FileAccess) Clone() FileAccess {
	return FileAccess{
		Base:    f.Base.Clone(),
		File:    f.File.Clone(),
		Process: f.Process.Clone(),
	}
}

func (f FileAccess) IsZero() bool {
	return f.Base.IsZero() && f.File.IsZero() && f.Process.IsZero()
}

func (f FileAccess) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		UUID       *string     `json:"uuid,omitempty"`
		Timestamp  *time.Time  `json:"timestamp,omitempty"`
		Note       *string     `json:"note,omitempty"`
		Metadata   *Metadata   `json:"metadata,omitempty"`
		Attenuator *Attenuator `json:"attenuator,omitempty"`
		Score      *Score      `json:"score,omitempty"`
		Background *Background `json:"background,omitempty"`
		Scenarios  *Scenarios  `json:"scenarios,omitempty"`

		File    *File    `json:"file,omitempty"`
		Process *Process `json:"process,omitempty"`
	}{}

	if !f.Base.IsZero() {
		created.UUID = &f.Base.UUID
		created.Timestamp = &f.Base.Timestamp

		if f.Base.Note != "" {
			created.Note = &f.Base.Note
		}
		if !f.Base.Metadata.IsZero() {
			created.Metadata = &f.Base.Metadata
		}
		if !f.Base.Attenuator.IsZero() {
			created.Attenuator = &f.Base.Attenuator
		}
		if !f.Base.Score.IsZero() {
			created.Score = &f.Base.Score
		}
		if !f.Base.Background.IsZero() {
			created.Background = &f.Base.Background
		}
		if !f.Base.Scenarios.IsZero() {
			created.Scenarios = &f.Base.Scenarios
		}
	}

	if !f.File.IsZero() {
		created.File = &f.File
	}
	if !f.Process.IsZero() {
		created.Process = &f.Process
	}

	return json.Marshal(created)
}

// Execution Detection Event.

type Execution struct {
	Base
	File    File    `json:"file"`
	Process Process `json:"process"`
}

func (e Execution) Clone() Execution {
	return Execution{
		Base:    e.Base.Clone(),
		File:    e.File.Clone(),
		Process: e.Process.Clone(),
	}
}

func (e Execution) IsZero() bool {
	return e.Base.IsZero() && e.File.IsZero() && e.Process.IsZero()
}

func (e Execution) MarshalJSON() ([]byte, error) {
	if e.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		UUID       *string     `json:"uuid,omitempty"`
		Timestamp  *time.Time  `json:"timestamp,omitempty"`
		Note       *string     `json:"note,omitempty"`
		Metadata   *Metadata   `json:"metadata,omitempty"`
		Attenuator *Attenuator `json:"attenuator,omitempty"`
		Score      *Score      `json:"score,omitempty"`
		Background *Background `json:"background,omitempty"`
		Scenarios  *Scenarios  `json:"scenarios,omitempty"`

		File    *File    `json:"file,omitempty"`
		Process *Process `json:"process,omitempty"`
	}{}

	if !e.Base.IsZero() {
		created.UUID = &e.Base.UUID
		created.Timestamp = &e.Base.Timestamp

		if e.Base.Note != "" {
			created.Note = &e.Base.Note
		}
		if !e.Base.Metadata.IsZero() {
			created.Metadata = &e.Base.Metadata
		}
		if !e.Base.Attenuator.IsZero() {
			created.Attenuator = &e.Base.Attenuator
		}
		if !e.Base.Score.IsZero() {
			created.Score = &e.Base.Score
		}
		if !e.Base.Background.IsZero() {
			created.Background = &e.Base.Background
		}
		if !e.Base.Scenarios.IsZero() {
			created.Scenarios = &e.Base.Scenarios
		}
	}

	if !e.File.IsZero() {
		created.File = &e.File
	}
	if !e.Process.IsZero() {
		created.Process = &e.Process
	}

	return json.Marshal(created)
}

// Network Peers Detection Event.

type NetworkPeer struct {
	Base
	Process Process `json:"process"` // Process triggering the detection with the flow.
	Flow    Flow    `json:"flow"`    // Network flow triggering the detection.
}

func (n NetworkPeer) Clone() NetworkPeer {
	return NetworkPeer{
		Base:    n.Base.Clone(),
		Process: n.Process.Clone(),
		Flow:    n.Flow.Clone(),
	}
}

func (n NetworkPeer) IsZero() bool {
	return n.Base.IsZero() && n.Process.IsZero() && n.Flow.IsZero()
}

func (n NetworkPeer) MarshalJSON() ([]byte, error) {
	if n.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		UUID       *string     `json:"uuid,omitempty"`
		Timestamp  *time.Time  `json:"timestamp,omitempty"`
		Note       *string     `json:"note,omitempty"`
		Metadata   *Metadata   `json:"metadata,omitempty"`
		Attenuator *Attenuator `json:"attenuator,omitempty"`
		Score      *Score      `json:"score,omitempty"`
		Background *Background `json:"background,omitempty"`
		Scenarios  *Scenarios  `json:"scenarios,omitempty"`

		Process *Process `json:"process,omitempty"`
		Flow    *Flow    `json:"flow,omitempty"`
	}{}

	if !n.Base.IsZero() {
		created.UUID = &n.Base.UUID
		created.Timestamp = &n.Base.Timestamp

		if n.Base.Note != "" {
			created.Note = &n.Base.Note
		}
		if !n.Base.Metadata.IsZero() {
			created.Metadata = &n.Base.Metadata
		}
		if !n.Base.Attenuator.IsZero() {
			created.Attenuator = &n.Base.Attenuator
		}
		if !n.Base.Score.IsZero() {
			created.Score = &n.Base.Score
		}
		if !n.Base.Background.IsZero() {
			created.Background = &n.Base.Background
		}
		if !n.Base.Scenarios.IsZero() {
			created.Scenarios = &n.Base.Scenarios
		}
	}

	if !n.Process.IsZero() {
		created.Process = &n.Process
	}
	if !n.Flow.IsZero() {
		created.Flow = &n.Flow
	}

	return json.Marshal(created)
}

// Network Flow Event.

type NetworkFlow struct {
	Base
	Process Process `json:"process"`
	Flow    Flow    `json:"flow"`
}

func (n NetworkFlow) Clone() NetworkFlow {
	return NetworkFlow{
		Base:    n.Base.Clone(),
		Process: n.Process.Clone(),
		Flow:    n.Flow.Clone(),
	}
}

func (n NetworkFlow) IsZero() bool {
	return n.Base.IsZero() && n.Process.IsZero() && n.Flow.IsZero()
}

func (n NetworkFlow) MarshalJSON() ([]byte, error) {
	if n.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		UUID       *string     `json:"uuid,omitempty"`
		Timestamp  *time.Time  `json:"timestamp,omitempty"`
		Note       *string     `json:"note,omitempty"`
		Metadata   *Metadata   `json:"metadata,omitempty"`
		Attenuator *Attenuator `json:"attenuator,omitempty"`
		Score      *Score      `json:"score,omitempty"`
		Background *Background `json:"background,omitempty"`
		Scenarios  *Scenarios  `json:"scenarios,omitempty"`

		Process *Process `json:"process,omitempty"`
		Flow    *Flow    `json:"flow,omitempty"`
	}{}

	if !n.Base.IsZero() {
		created.UUID = &n.Base.UUID
		created.Timestamp = &n.Base.Timestamp
		if n.Base.Note != "" {
			created.Note = &n.Base.Note
		}
		if !n.Base.Metadata.IsZero() {
			created.Metadata = &n.Base.Metadata
		}
		if !n.Base.Attenuator.IsZero() {
			created.Attenuator = &n.Base.Attenuator
		}
		if !n.Base.Score.IsZero() {
			created.Score = &n.Base.Score
		}
		if !n.Base.Background.IsZero() {
			created.Background = &n.Base.Background
		}
		if !n.Base.Scenarios.IsZero() {
			created.Scenarios = &n.Base.Scenarios
		}
	}

	if !n.Process.IsZero() {
		created.Process = &n.Process
	}
	if !n.Flow.IsZero() {
		created.Flow = &n.Flow
	}

	return json.Marshal(created)
}

// Drop IP Detection Event.

type DropIP struct {
	Base
	IP      string   `json:"ip"`      // The IP that was dropped.
	Names   []string `json:"names"`   // The names of the IP.
	Process Process  `json:"process"` // Process that triggered the drop.
	Flow    Flow     `json:"flow"`    // The flow that triggered the drop.
}

func (d DropIP) Clone() DropIP {
	return DropIP{
		Base:  d.Base.Clone(),
		IP:    d.IP,
		Names: append([]string(nil), d.Names...),
		Flow:  d.Flow.Clone(),
	}
}

func (d DropIP) IsZero() bool {
	return d.Base.IsZero() &&
		d.IP == "" &&
		len(d.Names) == 0 &&
		d.Flow.IsZero()
}

func (d DropIP) MarshalJSON() ([]byte, error) {
	if d.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		UUID       *string     `json:"uuid,omitempty"`
		Timestamp  *time.Time  `json:"timestamp,omitempty"`
		Note       *string     `json:"note,omitempty"`
		Metadata   *Metadata   `json:"metadata,omitempty"`
		Attenuator *Attenuator `json:"attenuator,omitempty"`
		Score      *Score      `json:"score,omitempty"`
		Background *Background `json:"background,omitempty"`
		Scenarios  *Scenarios  `json:"scenarios,omitempty"`

		IP      string   `json:"ip,omitempty"`
		Names   []string `json:"names,omitempty"`
		Process *Process `json:"process,omitempty"`
		Flow    *Flow    `json:"flow,omitempty"`
	}{
		IP:    d.IP,
		Names: d.Names,
	}

	if !d.Base.IsZero() {
		created.UUID = &d.Base.UUID
		created.Timestamp = &d.Base.Timestamp
		if d.Base.Note != "" {
			created.Note = &d.Base.Note
		}
		if !d.Base.Metadata.IsZero() {
			created.Metadata = &d.Base.Metadata
		}
		if !d.Base.Attenuator.IsZero() {
			created.Attenuator = &d.Base.Attenuator
		}
		if !d.Base.Score.IsZero() {
			created.Score = &d.Base.Score
		}
		if !d.Base.Background.IsZero() {
			created.Background = &d.Base.Background
		}
		if !d.Base.Scenarios.IsZero() {
			created.Scenarios = &d.Base.Scenarios
		}
	}

	if !d.Process.IsZero() {
		created.Process = &d.Process
	}
	if !d.Flow.IsZero() {
		created.Flow = &d.Flow
	}

	return json.Marshal(created)
}

// Process.

type Process struct {
	UUID       string     `json:"uuid"`        // Unique ID of the process.
	Start      time.Time  `json:"start"`       // The start time of the process.
	Exit       time.Time  `json:"exit"`        // The exit time of the process.
	Code       int        `json:"retcode"`     // The return code of the process.
	UID        uint       `json:"uid"`         // The user ID of the process.
	Pid        int        `json:"pid"`         // The process ID.
	Ppid       int        `json:"ppid"`        // The parent process ID.
	Comm       string     `json:"comm"`        // The command name.
	Cmd        string     `json:"cmd"`         // The command.
	Exe        string     `json:"exe"`         // The executable name.
	Args       string     `json:"args"`        // The arguments.
	Envs       string     `json:"envs"`        // The environment variables.
	Loader     string     `json:"loader"`      // The loader name.
	PrevExe    string     `json:"prev_exe"`    // The previous executable name.
	PrevArgs   string     `json:"prev_args"`   // The previous arguments.
	PrevEnvs   string     `json:"prev_envs"`   // The previous environment variables.
	PrevLoader string     `json:"prev_loader"` // The previous loader name.
	Namespaces Namespaces `json:"namespaces"`  // The namespaces.
	// Hashes for external indexing amongst other ongoing events.
	ProcessHash    uint32 `json:"process_hash"`     // The hash of the process.
	ParentHash     uint32 `json:"parent_hash"`      // The hash of the parent process.
	CommHash       uint32 `json:"comm_hash"`        // The hash of the command.
	ExeHash        uint32 `json:"exe_hash"`         // The hash of the executable.
	ArgsHash       uint32 `json:"args_hash"`        // The hash of the arguments.
	EnvsHash       uint32 `json:"envs_hash"`        // The hash of the environment variables.
	LoaderHash     uint32 `json:"loader_hash"`      // The hash of the loader.
	PrevExeHash    uint32 `json:"prev_exe_hash"`    // The hash of the previous executable.
	PrevArgsHash   uint32 `json:"prev_args_hash"`   // The hash of the previous arguments.
	PrevEnvsHash   uint32 `json:"prev_envs_hash"`   // The hash of the previous environment variables.
	PrevLoaderHash uint32 `json:"prev_loader_hash"` // The hash of the previous loader.
}

func (p Process) Clone() Process {
	return p
}

func (p Process) IsZero() bool {
	return p.UUID == "" &&
		p.Start.IsZero() &&
		p.Exit.IsZero() &&
		p.Code == 0 &&
		p.UID == 0 &&
		p.Pid == 0 &&
		p.Ppid == 0 &&
		p.Comm == "" &&
		p.Cmd == "" &&
		p.Exe == "" &&
		p.Args == "" &&
		p.Envs == "" &&
		p.Loader == "" &&
		p.PrevExe == "" &&
		p.PrevArgs == "" &&
		p.PrevEnvs == "" &&
		p.PrevLoader == "" &&
		p.Namespaces.IsZero() &&
		p.ProcessHash == 0 &&
		p.ParentHash == 0 &&
		p.CommHash == 0 &&
		p.ExeHash == 0 &&
		p.ArgsHash == 0 &&
		p.EnvsHash == 0 &&
		p.LoaderHash == 0 &&
		p.PrevExeHash == 0 &&
		p.PrevArgsHash == 0 &&
		p.PrevEnvsHash == 0 &&
		p.PrevLoaderHash == 0
}

func (p Process) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		UUID           string      `json:"uuid"`
		Start          time.Time   `json:"start"`
		Exit           time.Time   `json:"exit"`
		Code           int         `json:"retcode"`
		UID            uint        `json:"uid"`
		Pid            int         `json:"pid"`
		Ppid           int         `json:"ppid"`
		Comm           string      `json:"comm"`
		Cmd            string      `json:"cmd"`
		Exe            string      `json:"exe"`
		Args           string      `json:"args,omitempty"`
		Envs           string      `json:"envs,omitempty"`
		Loader         string      `json:"loader,omitempty"`
		PrevExe        string      `json:"prev_exe,omitempty"`
		PrevArgs       string      `json:"prev_args,omitempty"`
		PrevEnvs       string      `json:"prev_envs,omitempty"`
		PrevLoader     string      `json:"prev_loader,omitempty"`
		Namespaces     *Namespaces `json:"namespaces,omitempty"`
		ProcessHash    uint32      `json:"process_hash,omitempty"`
		ParentHash     uint32      `json:"parent_hash,omitempty"`
		CommHash       uint32      `json:"comm_hash,omitempty"`
		ExeHash        uint32      `json:"exe_hash,omitempty"`
		ArgsHash       uint32      `json:"args_hash,omitempty"`
		EnvsHash       uint32      `json:"envs_hash,omitempty"`
		LoaderHash     uint32      `json:"loader_hash,omitempty"`
		PrevExeHash    uint32      `json:"prev_exe_hash,omitempty"`
		PrevArgsHash   uint32      `json:"prev_args_hash,omitempty"`
		PrevEnvsHash   uint32      `json:"prev_envs_hash,omitempty"`
		PrevLoaderHash uint32      `json:"prev_loader_hash,omitempty"`
	}{
		UUID:           p.UUID,
		Start:          p.Start,
		Exit:           p.Exit,
		Code:           p.Code,
		UID:            p.UID,
		Pid:            p.Pid,
		Ppid:           p.Ppid,
		Comm:           p.Comm,
		Cmd:            p.Cmd,
		Exe:            p.Exe,
		Args:           p.Args,
		Envs:           p.Envs,
		Loader:         p.Loader,
		PrevExe:        p.PrevExe,
		PrevArgs:       p.PrevArgs,
		PrevEnvs:       p.PrevEnvs,
		PrevLoader:     p.PrevLoader,
		ProcessHash:    p.ProcessHash,
		ParentHash:     p.ParentHash,
		CommHash:       p.CommHash,
		ExeHash:        p.ExeHash,
		ArgsHash:       p.ArgsHash,
		EnvsHash:       p.EnvsHash,
		LoaderHash:     p.LoaderHash,
		PrevExeHash:    p.PrevExeHash,
		PrevArgsHash:   p.PrevArgsHash,
		PrevEnvsHash:   p.PrevEnvsHash,
		PrevLoaderHash: p.PrevLoaderHash,
	}

	if !p.Namespaces.IsZero() {
		created.Namespaces = &p.Namespaces
	}

	return json.Marshal(created)
}

// Namespaces.

type Namespaces struct {
	MNTNs    uint32 `json:"mnt_ns"`    // Mount namespace.
	PIDNs    uint32 `json:"pid_ns"`    // PID namespace.
	UTSNs    uint32 `json:"uts_ns"`    // UTS namespace.
	IPCNs    uint32 `json:"ipc_ns"`    // IPC namespace.
	NetNs    uint32 `json:"net_ns"`    // Network namespace.
	CgroupNs uint32 `json:"cgroup_ns"` // Cgroup namespace.
}

func (n Namespaces) IsZero() bool {
	return n.MNTNs == 0 &&
		n.PIDNs == 0 &&
		n.UTSNs == 0 &&
		n.IPCNs == 0 &&
		n.NetNs == 0 &&
		n.CgroupNs == 0
}

func (n Namespaces) MarshalJSON() ([]byte, error) {
	if n.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		MNTNs    uint32 `json:"mnt_ns,omitempty"`
		PIDNs    uint32 `json:"pid_ns,omitempty"`
		UTSNs    uint32 `json:"uts_ns,omitempty"`
		IPCNs    uint32 `json:"ipc_ns,omitempty"`
		NetNs    uint32 `json:"net_ns,omitempty"`
		CgroupNs uint32 `json:"cgroup_ns,omitempty"`
	}{
		MNTNs:    n.MNTNs,
		PIDNs:    n.PIDNs,
		UTSNs:    n.UTSNs,
		IPCNs:    n.IPCNs,
		NetNs:    n.NetNs,
		CgroupNs: n.CgroupNs,
	})
}

// File.

type File struct {
	UUID        string          `json:"uuid"`        // UUID of the file.
	Path        string          `json:"path"`        // Absolute path to the file.
	Dir         string          `json:"dir"`         // Directory containing the file.
	Base        string          `json:"basename"`    // Base name of the file.
	Type        string          `json:"type"`        // File type: regular, directory, symlink, socket, block, char, fifo.
	Owner       FileOwner       `json:"owner"`       // File owner.
	Actions     FileActions     `json:"actions"`     // Detailed actions performed on the file.
	Permissions FilePermissions `json:"permissions"` // File permissions.
	Metadata    FileMetadata    `json:"metadata"`    // File metadata.
	// Hashes for external indexing amongst other ongoing events.
	FileHash uint32 `json:"file_hash"` // The hash of the file.
	DirHash  uint32 `json:"dir_hash"`  // The hash of the directory.
	BaseHash uint32 `json:"base_hash"` // The hash of the base name.
}

func (f File) Clone() File {
	return File{
		UUID:        f.UUID,
		Path:        f.Path,
		Dir:         f.Dir,
		Base:        f.Base,
		Type:        f.Type,
		Owner:       f.Owner.Clone(),
		Actions:     f.Actions.Clone(),
		Permissions: f.Permissions.Clone(),
		Metadata:    f.Metadata.Clone(),
		FileHash:    f.FileHash,
		DirHash:     f.DirHash,
		BaseHash:    f.BaseHash,
	}
}

func (f File) IsZero() bool {
	return f.UUID == "" &&
		f.Path == "" &&
		f.Dir == "" &&
		f.Base == "" &&
		f.Type == "" &&
		f.Owner.IsZero() &&
		f.Actions.IsZero() &&
		f.Permissions.IsZero() &&
		f.Metadata.IsZero() &&
		f.FileHash == 0 &&
		f.DirHash == 0 &&
		f.BaseHash == 0
}

func (f File) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		UUID        string           `json:"uuid"`
		Path        string           `json:"path"`
		Dir         string           `json:"dir"`
		Base        string           `json:"basename"`
		Type        string           `json:"type"`
		Owner       FileOwner        `json:"owner"`
		Actions     *FileActions     `json:"actions,omitempty"`
		Permissions *FilePermissions `json:"permissions,omitempty"`
		Metadata    *FileMetadata    `json:"metadata,omitempty"`
		FileHash    uint32           `json:"file_hash,omitempty"`
		DirHash     uint32           `json:"dir_hash,omitempty"`
		BaseHash    uint32           `json:"base_hash,omitempty"`
	}{
		UUID:     f.UUID,
		Path:     f.Path,
		Dir:      f.Dir,
		Base:     f.Base,
		Type:     f.Type,
		Owner:    f.Owner,
		FileHash: f.FileHash,
		DirHash:  f.DirHash,
		BaseHash: f.BaseHash,
	}

	if !f.Actions.IsZero() {
		created.Actions = &f.Actions
	}
	if !f.Permissions.IsZero() {
		created.Permissions = &f.Permissions
	}
	if !f.Metadata.IsZero() {
		created.Metadata = &f.Metadata
	}

	return json.Marshal(created)
}

// File Owner.

type FileOwner struct {
	UID uint32 `json:"uid"` // User ID of owner.
	GID uint32 `json:"gid"` // Group ID of owner.
}

func (f FileOwner) Clone() FileOwner {
	return FileOwner{
		UID: f.UID,
		GID: f.GID,
	}
}

func (f FileOwner) IsZero() bool {
	// Note: root user and group have zero values for UID and GID.
	return false
}

func (f FileOwner) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		UID uint32 `json:"uid"`
		GID uint32 `json:"gid"`
	}{
		UID: f.UID,
		GID: f.GID,
	})
}

// File Permissions.

type FilePermissions struct {
	Mode       string `json:"mode"`        // File mode as string (e.g., "rwxr-xr-x").
	OwnerRead  bool   `json:"owner_read"`  // Owner can read.
	OwnerWrite bool   `json:"owner_write"` // Owner can write.
	OwnerExec  bool   `json:"owner_exec"`  // Owner can execute.
	GroupRead  bool   `json:"group_read"`  // Group can read.
	GroupWrite bool   `json:"group_write"` // Group can write.
	GroupExec  bool   `json:"group_exec"`  // Group can execute.
	OtherRead  bool   `json:"other_read"`  // Others can read.
	OtherWrite bool   `json:"other_write"` // Others can write.
	OtherExec  bool   `json:"other_exec"`  // Others can execute.
	Setuid     bool   `json:"setuid"`      // Setuid bit set.
	Setgid     bool   `json:"setgid"`      // Setgid bit set.
	Sticky     bool   `json:"sticky"`      // Sticky bit set.
}

func (f FilePermissions) Clone() FilePermissions {
	return FilePermissions{
		Mode:       f.Mode,
		OwnerRead:  f.OwnerRead,
		OwnerWrite: f.OwnerWrite,
		OwnerExec:  f.OwnerExec,
		GroupRead:  f.GroupRead,
		GroupWrite: f.GroupWrite,
		GroupExec:  f.GroupExec,
		OtherRead:  f.OtherRead,
		OtherWrite: f.OtherWrite,
		OtherExec:  f.OtherExec,
		Setuid:     f.Setuid,
		Setgid:     f.Setgid,
		Sticky:     f.Sticky,
	}
}

func (f FilePermissions) IsZero() bool {
	return f.Mode == "" &&
		!f.OwnerRead &&
		!f.OwnerWrite &&
		!f.OwnerExec &&
		!f.GroupRead &&
		!f.GroupWrite &&
		!f.GroupExec &&
		!f.OtherRead &&
		!f.OtherWrite &&
		!f.OtherExec
}

func (f FilePermissions) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Mode       string `json:"mode"`
		OwnerRead  bool   `json:"owner_read"`
		OwnerWrite bool   `json:"owner_write"`
		OwnerExec  bool   `json:"owner_exec"`
		GroupRead  bool   `json:"group_read"`
		GroupWrite bool   `json:"group_write"`
		GroupExec  bool   `json:"group_exec"`
		OtherRead  bool   `json:"other_read"`
		OtherWrite bool   `json:"other_write"`
		OtherExec  bool   `json:"other_exec"`
		Setuid     bool   `json:"setuid"`
		Setgid     bool   `json:"setgid"`
		Sticky     bool   `json:"sticky"`
	}{
		Mode:       f.Mode,
		OwnerRead:  f.OwnerRead,
		OwnerWrite: f.OwnerWrite,
		OwnerExec:  f.OwnerExec,
		GroupRead:  f.GroupRead,
		GroupWrite: f.GroupWrite,
		GroupExec:  f.GroupExec,
		OtherRead:  f.OtherRead,
		OtherWrite: f.OtherWrite,
		OtherExec:  f.OtherExec,
		Setuid:     f.Setuid,
		Setgid:     f.Setgid,
		Sticky:     f.Sticky,
	})
}

// File Metadata.

type FileMetadata struct {
	Size     int64     `json:"size"`     // File size in bytes.
	Access   time.Time `json:"access"`   // Last access time.
	Change   time.Time `json:"change"`   // Last modification time.
	Creation time.Time `json:"creation"` // Creation time.
}

func (f FileMetadata) Clone() FileMetadata {
	return FileMetadata{
		Size:     f.Size,
		Access:   f.Access,
		Change:   f.Change,
		Creation: f.Creation,
	}
}

func (f FileMetadata) IsZero() bool {
	return f.Size == 0 &&
		f.Access.IsZero() &&
		f.Change.IsZero() &&
		f.Creation.IsZero()
}

func (f FileMetadata) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Size     int64     `json:"size,omitempty"`
		Access   time.Time `json:"access,omitempty"`
		Change   time.Time `json:"change,omitempty"`
		Creation time.Time `json:"creation,omitempty"`
	}{
		Size:     f.Size,
		Access:   f.Access,
		Change:   f.Change,
		Creation: f.Creation,
	})
}

// File Actions.

type FileActions struct {
	Actions  []string `json:"actions"`  // List of actions performed on the file.
	Open     bool     `json:"open"`     // File was opened.
	Read     bool     `json:"read"`     // File was read.
	Write    bool     `json:"write"`    // File was written.
	Exec     bool     `json:"exec"`     // File was executed (execve).
	Create   bool     `json:"create"`   // File was created.
	Unlink   bool     `json:"unlink"`   // File was deleted (unlinked).
	Rename   bool     `json:"rename"`   // File was renamed.
	Link     bool     `json:"link"`     // File was hardlinked.
	Truncate bool     `json:"truncate"` // File was truncated.
	Fsync    bool     `json:"fsync"`    // File was fsynced.
	Flock    bool     `json:"flock"`    // File was flocked.
	Mmap     bool     `json:"mmap"`     // File was mmapped.
	Close    bool     `json:"close"`    // File was closed.
	Async    bool     `json:"async"`    // Async I/O performed.
	Seek     bool     `json:"seek"`     // File was llseeked.
}

func (f FileActions) Clone() FileActions {
	return FileActions{
		Actions:  append([]string(nil), f.Actions...),
		Open:     f.Open,
		Read:     f.Read,
		Write:    f.Write,
		Exec:     f.Exec,
		Create:   f.Create,
		Unlink:   f.Unlink,
		Rename:   f.Rename,
		Link:     f.Link,
		Truncate: f.Truncate,
		Fsync:    f.Fsync,
		Flock:    f.Flock,
		Mmap:     f.Mmap,
		Close:    f.Close,
		Async:    f.Async,
		Seek:     f.Seek,
	}
}

func (f FileActions) IsZero() bool {
	return len(f.Actions) == 0 &&
		!f.Open &&
		!f.Read &&
		!f.Write &&
		!f.Exec &&
		!f.Create &&
		!f.Unlink &&
		!f.Rename &&
		!f.Link &&
		!f.Truncate &&
		!f.Fsync &&
		!f.Flock &&
		!f.Mmap &&
		!f.Close &&
		!f.Async &&
		!f.Seek
}

func (f FileActions) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(struct {
		Actions  []string `json:"actions,omitempty"`
		Open     bool     `json:"open,omitempty"`
		Read     bool     `json:"read,omitempty"`
		Write    bool     `json:"write,omitempty"`
		Exec     bool     `json:"exec,omitempty"`
		Create   bool     `json:"create,omitempty"`
		Unlink   bool     `json:"unlink,omitempty"`
		Rename   bool     `json:"rename,omitempty"`
		Link     bool     `json:"link,omitempty"`
		Truncate bool     `json:"truncate,omitempty"`
		Fsync    bool     `json:"fsync,omitempty"`
		Flock    bool     `json:"flock,omitempty"`
		Mmap     bool     `json:"mmap,omitempty"`
		Close    bool     `json:"close,omitempty"`
		Async    bool     `json:"async,omitempty"`
		Seek     bool     `json:"seek,omitempty"`
	}{
		// Note: we intentionally rely on omitempty here; IsZero() still controls null output.

		Actions:  f.Actions,
		Open:     f.Open,
		Read:     f.Read,
		Write:    f.Write,
		Exec:     f.Exec,
		Create:   f.Create,
		Unlink:   f.Unlink,
		Rename:   f.Rename,
		Link:     f.Link,
		Truncate: f.Truncate,
		Fsync:    f.Fsync,
		Flock:    f.Flock,
		Mmap:     f.Mmap,
		Close:    f.Close,
		Async:    f.Async,
		Seek:     f.Seek,
	})
}

// File Aggregate.

type FileAggregate struct {
	Root FSDir `json:"root"` // Root directory of the file tree.
}

func (f FileAggregate) Clone() FileAggregate {
	return FileAggregate{
		Root: f.Root.Clone(),
	}
}

func (f FileAggregate) IsZero() bool {
	return f.Root.IsZero()
}

func (f FileAggregate) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}
	type Alias FileAggregate
	return json.Marshal(Alias(f))
}

// FSDir.

type FSDir struct {
	Path    string   `json:"path"`     // Absolute path of the directory.
	Base    string   `json:"base"`     // Base name of the directory.
	Dirs    []FSDir  `json:"dirs"`     // Subdirectories.
	Files   []FSFile `json:"files"`    // Files in this directory.
	DirHash uint32   `json:"dir_hash"` // The hash of the directory.
}

func (f FSDir) Clone() FSDir {
	dirs := make([]FSDir, len(f.Dirs))
	for i, d := range f.Dirs {
		dirs[i] = d.Clone()
	}
	files := make([]FSFile, len(f.Files))
	for i, file := range f.Files {
		files[i] = file.Clone()
	}
	return FSDir{
		Path:    f.Path,
		Base:    f.Base,
		Dirs:    dirs,
		Files:   files,
		DirHash: f.DirHash,
	}
}

func (f FSDir) IsZero() bool {
	return f.Path == "" &&
		f.Base == "" &&
		len(f.Dirs) == 0 &&
		len(f.Files) == 0 &&
		f.DirHash == 0
}

func (f FSDir) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Path    string   `json:"path,omitempty"`
		Base    string   `json:"base,omitempty"`
		Dirs    []FSDir  `json:"dirs,omitempty"`
		Files   []FSFile `json:"files,omitempty"`
		DirHash uint32   `json:"dir_hash,omitempty"`
	}{
		Path:    f.Path,
		Base:    f.Base,
		Dirs:    f.Dirs,
		Files:   f.Files,
		DirHash: f.DirHash,
	})
}

// FSFile.

type FSFile struct {
	Path     string       `json:"path"`      // Absolute path of the file.
	Base     string       `json:"base"`      // Base name of the file.
	Actions  []string     `json:"actions"`   // Actions taken on the file.
	Mode     string       `json:"mode"`      // File mode.
	Owner    FileOwner    `json:"owner"`     // File owner.
	Metadata FileMetadata `json:"metadata"`  // File metadata.
	FileHash uint32       `json:"file_hash"` // The hash of the file.
	DirHash  uint32       `json:"dir_hash"`  // The hash of the directory.
	BaseHash uint32       `json:"base_hash"` // The hash of the base name.
}

func (f FSFile) Clone() FSFile {
	return FSFile{
		Path:     f.Path,
		Base:     f.Base,
		Actions:  append([]string(nil), f.Actions...),
		Mode:     f.Mode,
		Owner:    f.Owner,
		Metadata: f.Metadata,
		FileHash: f.FileHash,
		DirHash:  f.DirHash,
		BaseHash: f.BaseHash,
	}
}

func (f FSFile) IsZero() bool {
	return f.Path == "" &&
		f.Base == "" &&
		len(f.Actions) == 0 &&
		f.Mode == "" &&
		f.Owner.IsZero() &&
		f.Metadata.IsZero() &&
		f.FileHash == 0 &&
		f.DirHash == 0 &&
		f.BaseHash == 0
}

func (f FSFile) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		Path     string        `json:"path"`
		Base     string        `json:"base"`
		Actions  []string      `json:"actions"`
		Owner    FileOwner     `json:"owner"`
		Mode     string        `json:"mode"`
		Metadata *FileMetadata `json:"metadata,omitempty"`
		FileHash uint32        `json:"file_hash"`
		DirHash  uint32        `json:"dir_hash"`
		BaseHash uint32        `json:"base_hash"`
	}{
		Path:     f.Path,
		Base:     f.Base,
		Actions:  f.Actions,
		Owner:    f.Owner,
		Mode:     f.Mode,
		FileHash: f.FileHash,
		DirHash:  f.DirHash,
		BaseHash: f.BaseHash,
	}

	if !f.Metadata.IsZero() {
		created.Metadata = &f.Metadata
	}

	return json.Marshal(created)
}

// Flow.

type Flow struct {
	UUID        string `json:"uuid"`         // UUID of the flow.
	IPVersion   int    `json:"ip_version"`   // IP version.
	Proto       string `json:"proto"`        // Protocol.
	ICMP        ICMP   `json:"icmp"`         // ICMP.
	Local       Node   `json:"local"`        // Local node.
	Remote      Node   `json:"remote"`       // Remote node.
	ServicePort int    `json:"service_port"` // Service port.
	Flags       Flags  `json:"flags"`        // Flags.
	Phase       Phase  `json:"phase"`        // Flow phase.
	// Hashes for external indexing amongst other ongoing events.
	FlowHash uint32 `json:"flow_hash"` // The hash of the flow.
}

func (f Flow) Clone() Flow {
	return Flow{
		UUID:        f.UUID,
		IPVersion:   f.IPVersion,
		Proto:       f.Proto,
		ICMP:        f.ICMP,
		Local:       f.Local.Clone(),
		Remote:      f.Remote.Clone(),
		ServicePort: f.ServicePort,
		Flags:       f.Flags,
		Phase:       f.Phase,
		FlowHash:    f.FlowHash,
	}
}

func (f Flow) IsZero() bool {
	return f.UUID == "" &&
		f.IPVersion == 0 &&
		f.Proto == "" &&
		f.ICMP.IsZero() &&
		f.Local.IsZero() &&
		f.Remote.IsZero() &&
		f.ServicePort == 0 &&
		f.Flags.IsZero() &&
		f.Phase.IsZero() &&
		f.FlowHash == 0
}

func (f Flow) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		UUID        string `json:"uuid"`
		IPVersion   int    `json:"ip_version"`
		Proto       string `json:"proto"`
		ICMP        *ICMP  `json:"icmp,omitempty"`
		Local       *Node  `json:"local,omitempty"`
		Remote      *Node  `json:"remote,omitempty"`
		ServicePort int    `json:"service_port,omitempty"`
		Flags       *Flags `json:"flags,omitempty"`
		Phase       *Phase `json:"phase,omitempty"`
		FlowHash    uint32 `json:"flow_hash,omitempty"`
	}{
		UUID:      f.UUID,
		IPVersion: f.IPVersion,
		Proto:     f.Proto,
		FlowHash:  f.FlowHash,
	}

	if !f.ICMP.IsZero() {
		created.ICMP = &f.ICMP
	}
	if !f.Local.IsZero() {
		created.Local = &f.Local
	}
	if !f.Remote.IsZero() {
		created.Remote = &f.Remote
	}
	if f.ServicePort != 0 {
		created.ServicePort = f.ServicePort
	}
	if !f.Flags.IsZero() {
		created.Flags = &f.Flags
	}
	if !f.Phase.IsZero() {
		created.Phase = &f.Phase
	}

	return json.Marshal(created)
}

type ICMP struct {
	Type string `json:"type"` // ICMP type.
	Code string `json:"code"` // ICMP code.
}

func (i ICMP) IsZero() bool {
	return i.Type == "" && i.Code == ""
}

func (i ICMP) MarshalJSON() ([]byte, error) {
	if i.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Type string `json:"type"`
		Code string `json:"code"`
	}{
		Type: i.Type,
		Code: i.Code,
	})
}

type Node struct {
	Address string   `json:"address"` // IP address.
	Name    string   `json:"name"`    // DNS name.
	Names   []string `json:"names"`   // DNS names.
	Port    int      `json:"port"`    // Port.
}

func (n Node) Clone() Node {
	return Node{
		Address: n.Address,
		Name:    n.Name,
		Names:   append([]string(nil), n.Names...),
		Port:    n.Port,
	}
}

func (n Node) IsZero() bool {
	return n.Address == "" &&
		n.Name == "" &&
		len(n.Names) == 0 &&
		n.Port == 0
}

func (n Node) MarshalJSON() ([]byte, error) {
	if n.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Address string   `json:"address"`
		Name    string   `json:"name"`
		Names   []string `json:"names,omitempty"`
		Port    int      `json:"port"`
	}{
		Address: n.Address,
		Name:    n.Name,
		Names:   n.Names,
		Port:    n.Port,
	})
}

type Flags struct {
	Ingress    bool `json:"ingress"`    // An ingress packet has been received.
	Egress     bool `json:"egress"`     // An egress packet has been sent.
	Incoming   bool `json:"incoming"`   // Connection is incoming.
	Outgoing   bool `json:"outgoing"`   // Connection is outgoing.
	Started    bool `json:"started"`    // Connection has been started.
	Ongoing    bool `json:"ongoing"`    // Connection is ongoing.
	Ended      bool `json:"ended"`      // Connection has been ended.
	Terminator bool `json:"terminator"` // Local node has terminated the connection.
	Terminated bool `json:"terminated"` // Remote node has terminated the connection.
}

func (f Flags) IsZero() bool {
	return !f.Ingress &&
		!f.Egress &&
		!f.Incoming &&
		!f.Outgoing &&
		!f.Started &&
		!f.Ongoing &&
		!f.Ended &&
		!f.Terminator &&
		!f.Terminated
}

func (f Flags) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Ingress    bool `json:"ingress"`
		Egress     bool `json:"egress"`
		Incoming   bool `json:"incoming"`
		Outgoing   bool `json:"outgoing"`
		Started    bool `json:"started"`
		Ongoing    bool `json:"ongoing"`
		Ended      bool `json:"ended"`
		Terminator bool `json:"terminator"`
		Terminated bool `json:"terminated"`
	}{
		Ingress:    f.Ingress,
		Egress:     f.Egress,
		Incoming:   f.Incoming,
		Outgoing:   f.Outgoing,
		Started:    f.Started,
		Ongoing:    f.Ongoing,
		Ended:      f.Ended,
		Terminator: f.Terminator,
		Terminated: f.Terminated,
	})
}

type Phase struct {
	Direction  string `json:"direction"`    // Direction of the flow.
	InitatedBy string `json:"initiated_by"` // Who initiated the flow.
	Status     string `json:"status"`       // Status of the flow.
	EndedBy    string `json:"ended_by"`     // Who ended the flow.
}

func (p Phase) IsZero() bool {
	return p.Direction == "" &&
		p.InitatedBy == "" &&
		p.Status == "" &&
		p.EndedBy == ""
}

func (p Phase) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Direction  string `json:"direction"`
		InitatedBy string `json:"initiated_by"`
		Status     string `json:"status"`
		EndedBy    string `json:"ended_by"`
	}{
		Direction:  p.Direction,
		InitatedBy: p.InitatedBy,
		Status:     p.Status,
		EndedBy:    p.EndedBy,
	})
}

// Node Pair Key.

type NodePairKey struct {
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
}

// Flow Aggregate.

type FlowAggregate struct {
	IPVersion int                 `json:"ip_version"` // IP version.
	Protocols []ProtocolAggregate `json:"protocols"`  // List of protocol aggregates.
}

func (f FlowAggregate) Clone() FlowAggregate {
	protocols := make([]ProtocolAggregate, len(f.Protocols))
	for i, p := range f.Protocols {
		protocols[i] = p.Clone()
	}
	return FlowAggregate{
		IPVersion: f.IPVersion,
		Protocols: protocols,
	}
}

func (f FlowAggregate) IsZero() bool {
	return f.IPVersion == 0 && len(f.Protocols) == 0
}

func (f FlowAggregate) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		IPVersion int                 `json:"ip_version,omitempty"`
		Protocols []ProtocolAggregate `json:"protocols,omitempty"`
	}{
		IPVersion: f.IPVersion,
		Protocols: f.Protocols,
	})
}

// Protocol Aggregate.

type ProtocolAggregate struct {
	Proto string                   `json:"proto"` // Protocol (e.g., TCP, UDP, ICMP).
	Pairs []ProtocolLocalRemoteAgg `json:"pairs"` // List of unique local/remote node pairs for this protocol.
	ICMPs []ICMP                   `json:"icmps"` // ICMP types/codes if protocol is ICMP.
}

func (p ProtocolAggregate) Clone() ProtocolAggregate {
	pairs := make([]ProtocolLocalRemoteAgg, len(p.Pairs))
	for i, pair := range p.Pairs {
		pairs[i] = pair.Clone()
	}
	icmps := make([]ICMP, len(p.ICMPs))
	copy(icmps, p.ICMPs)
	return ProtocolAggregate{
		Proto: p.Proto,
		Pairs: pairs,
		ICMPs: icmps,
	}
}

func (p ProtocolAggregate) IsZero() bool {
	return p.Proto == "" &&
		len(p.Pairs) == 0 &&
		len(p.ICMPs) == 0
}

func (p ProtocolAggregate) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Proto string                   `json:"proto,omitempty"`
		Pairs []ProtocolLocalRemoteAgg `json:"pairs,omitempty"`
		ICMPs []ICMP                   `json:"icmps,omitempty"`
	}{
		Proto: p.Proto,
		Pairs: p.Pairs,
		ICMPs: p.ICMPs,
	})
}

// Protocol Local/Remote Aggregate.

type ProtocolLocalRemoteAgg struct {
	Nodes      LocalRemotePair `json:"nodes"`       // Local and remote nodes.
	PortMatrix []PortCommAgg   `json:"port_matrix"` // All ports used in flows between the nodes.
}

func (p ProtocolLocalRemoteAgg) Clone() ProtocolLocalRemoteAgg {
	portMatrix := make([]PortCommAgg, len(p.PortMatrix))
	copy(portMatrix, p.PortMatrix)
	return ProtocolLocalRemoteAgg{
		Nodes:      p.Nodes.Clone(),
		PortMatrix: portMatrix,
	}
}

func (p ProtocolLocalRemoteAgg) IsZero() bool {
	return p.Nodes.IsZero() && len(p.PortMatrix) == 0
}

func (p ProtocolLocalRemoteAgg) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		Nodes      *LocalRemotePair `json:"nodes,omitempty"`
		PortMatrix []PortCommAgg    `json:"port_matrix,omitempty"`
	}{
		PortMatrix: p.PortMatrix,
	}

	if !p.Nodes.IsZero() {
		created.Nodes = &p.Nodes
	}

	return json.Marshal(created)
}

// Protocol Node.

type ProtocolNode struct {
	Address string   `json:"address"` // IP address.
	Name    string   `json:"name"`    // DNS name.
	Names   []string `json:"names"`   // DNS names.
}

func (p ProtocolNode) Clone() ProtocolNode {
	return ProtocolNode{
		Address: p.Address,
		Name:    p.Name,
		Names:   append([]string(nil), p.Names...),
	}
}

func (p ProtocolNode) IsZero() bool {
	return p.Address == "" &&
		p.Name == "" &&
		len(p.Names) == 0
}

func (p ProtocolNode) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Address string   `json:"address"`
		Name    string   `json:"name,omitempty"`
		Names   []string `json:"names,omitempty"`
	}{
		Address: p.Address,
		Name:    p.Name,
		Names:   p.Names,
	})
}

// Local/Remote Pair.

type LocalRemotePair struct {
	Local  ProtocolNode `json:"local"`  // Local node.
	Remote ProtocolNode `json:"remote"` // Remote node.
}

func (l LocalRemotePair) Clone() LocalRemotePair {
	return LocalRemotePair{
		Local:  l.Local.Clone(),
		Remote: l.Remote.Clone(),
	}
}

func (l LocalRemotePair) IsZero() bool {
	return l.Local.IsZero() && l.Remote.IsZero()
}

func (l LocalRemotePair) MarshalJSON() ([]byte, error) {
	if l.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Local  ProtocolNode `json:"local"`
		Remote ProtocolNode `json:"remote"`
	}{
		Local:  l.Local,
		Remote: l.Remote,
	})
}

// Port Communication Aggregate.

type PortCommAgg struct {
	SrcPort int   `json:"src_port"` // Source port.
	DstPort int   `json:"dst_port"` // Destination port.
	Phase   Phase `json:"phase"`    // Flow phase.
}

func (p PortCommAgg) IsZero() bool {
	return p.SrcPort == 0 &&
		p.DstPort == 0 &&
		p.Phase.IsZero()
}

func (p PortCommAgg) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		SrcPort int    `json:"src_port"`
		DstPort int    `json:"dst_port"`
		Phase   *Phase `json:"phase,omitempty"`
	}{
		SrcPort: p.SrcPort,
		DstPort: p.DstPort,
	}

	if !p.Phase.IsZero() {
		created.Phase = &p.Phase
	}

	return json.Marshal(created)
}

// Containers and Namespaces.

type Containers struct {
	MntNamespaceIDs    []ContainerID `json:"mnt_namespace_ids"`    // Mount namespace IDs.
	PidNamespaceIDs    []ContainerID `json:"pid_namespace_ids"`    // PID namespace IDs.
	UtsNamespaceIDs    []ContainerID `json:"uts_namespace_ids"`    // UTS namespace IDs.
	IpcNamespaceIDs    []ContainerID `json:"ipc_namespace_ids"`    // IPC namespace IDs.
	NetNamespaceIDs    []ContainerID `json:"net_namespace_ids"`    // Net namespace IDs.
	CgroupNamespaceIDs []ContainerID `json:"cgroup_namespace_ids"` // Cgroup namespace IDs.
	Containers         []Container   `json:"containers"`           // Containers.
}

func (c Containers) Clone() Containers {
	mnt := make([]ContainerID, len(c.MntNamespaceIDs))
	copy(mnt, c.MntNamespaceIDs)
	pid := make([]ContainerID, len(c.PidNamespaceIDs))
	copy(pid, c.PidNamespaceIDs)
	uts := make([]ContainerID, len(c.UtsNamespaceIDs))
	copy(uts, c.UtsNamespaceIDs)
	ipc := make([]ContainerID, len(c.IpcNamespaceIDs))
	copy(ipc, c.IpcNamespaceIDs)
	net := make([]ContainerID, len(c.NetNamespaceIDs))
	copy(net, c.NetNamespaceIDs)
	cgroup := make([]ContainerID, len(c.CgroupNamespaceIDs))
	copy(cgroup, c.CgroupNamespaceIDs)
	containers := make([]Container, len(c.Containers))
	for i, container := range c.Containers {
		containers[i] = container.Clone()
	}
	return Containers{
		MntNamespaceIDs:    mnt,
		PidNamespaceIDs:    pid,
		UtsNamespaceIDs:    uts,
		IpcNamespaceIDs:    ipc,
		NetNamespaceIDs:    net,
		CgroupNamespaceIDs: cgroup,
		Containers:         containers,
	}
}

func (c Containers) IsZero() bool {
	return len(c.MntNamespaceIDs) == 0 &&
		len(c.PidNamespaceIDs) == 0 &&
		len(c.UtsNamespaceIDs) == 0 &&
		len(c.IpcNamespaceIDs) == 0 &&
		len(c.NetNamespaceIDs) == 0 &&
		len(c.CgroupNamespaceIDs) == 0 &&
		len(c.Containers) == 0
}

func (c Containers) MarshalJSON() ([]byte, error) {
	if c.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		MntNamespaceIDs    []ContainerID `json:"mnt_namespace_ids,omitempty"`
		PidNamespaceIDs    []ContainerID `json:"pid_namespace_ids,omitempty"`
		UtsNamespaceIDs    []ContainerID `json:"uts_namespace_ids,omitempty"`
		IpcNamespaceIDs    []ContainerID `json:"ipc_namespace_ids,omitempty"`
		NetNamespaceIDs    []ContainerID `json:"net_namespace_ids,omitempty"`
		CgroupNamespaceIDs []ContainerID `json:"cgroup_namespace_ids,omitempty"`
		Containers         []Container   `json:"containers,omitempty"`
	}{
		MntNamespaceIDs:    c.MntNamespaceIDs,
		PidNamespaceIDs:    c.PidNamespaceIDs,
		UtsNamespaceIDs:    c.UtsNamespaceIDs,
		IpcNamespaceIDs:    c.IpcNamespaceIDs,
		NetNamespaceIDs:    c.NetNamespaceIDs,
		CgroupNamespaceIDs: c.CgroupNamespaceIDs,
		Containers:         c.Containers,
	})
}

// Container ID.

type ContainerID struct {
	Name string `json:"name"` // Container name.
	ID   string `json:"id"`   // Container ID.
}

func (c ContainerID) GetName() string {
	return c.Name
}

func (c ContainerID) GetID() string {
	return c.ID
}

func (c ContainerID) IsZero() bool {
	return c.Name == "" && c.ID == ""
}

func (c ContainerID) MarshalJSON() ([]byte, error) {
	if c.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		ID   string `json:"id"`
		Name string `json:"name,omitempty"`
	}{
		ID:   c.ID,
		Name: c.Name,
	})
}

// Mount.

type Mount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Type        string `json:"type"`
}

func (m Mount) Clone() Mount {
	return Mount{
		Source:      m.Source,
		Destination: m.Destination,
		Type:        m.Type,
	}
}

func (m Mount) IsZero() bool {
	return m.Source == "" &&
		m.Destination == "" &&
		m.Type == ""
}

func (m Mount) MarshalJSON() ([]byte, error) {
	if m.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
		Type        string `json:"type"`
	}{
		Source:      m.Source,
		Destination: m.Destination,
		Type:        m.Type,
	})
}

// Container.

type Container struct {
	ID           string     `json:"id"`            // Container ID.
	Name         string     `json:"name"`          // Container name.
	HostName     string     `json:"hostname"`      // Host name.
	ImageID      string     `json:"image_id"`      // Image ID.
	Image        string     `json:"image"`         // Image name.
	Version      string     `json:"version"`       // Image version.
	Runtime      string     `json:"runtime"`       // Container runtime ("docker", "containerd", etc).
	Driver       string     `json:"driver"`        // Container driver ("overlay2", "aufs", etc).
	PID          int        `json:"pid"`           // Process ID.
	ExitCode     int        `json:"exit_code"`     // Exit code.
	Status       string     `json:"status"`        // Current status.
	IsAttached   bool       `json:"is_attached"`   // Whether the container is attached to the host.
	Path         string     `json:"path"`          // Path to the container executable.
	Cwd          string     `json:"cwd"`           // Current working directory.
	CreatedAt    time.Time  `json:"created_at"`    // Creation time.
	StartedAt    time.Time  `json:"started_at"`    // Start time.
	FinishedAt   time.Time  `json:"finished_at"`   // Finish time.
	Mounts       []Mount    `json:"mounts"`        // Mounts.
	NetworkMode  string     `json:"network_mode"`  // Network mode.
	CgroupnsMode string     `json:"cgroupns_mode"` // Cgroup namespace mode.
	IpcMode      string     `json:"ipc_mode"`      // IPC mode.
	PidMode      string     `json:"pid_mode"`      // PID mode.
	UsernsMode   string     `json:"userns_mode"`   // User namespace mode.
	UTSMode      string     `json:"uts_mode"`      // UTS namespace mode.
	Env          []string   `json:"env"`           // Environment variables.
	Cmd          []string   `json:"cmd"`           // Command.
	Namespaces   Namespaces `json:"namespaces"`    // Namespaces.
}

func (c Container) Clone() Container {
	mounts := make([]Mount, len(c.Mounts))
	for i, m := range c.Mounts {
		mounts[i] = m.Clone()
	}
	return Container{
		ID:           c.ID,
		Name:         c.Name,
		HostName:     c.HostName,
		ImageID:      c.ImageID,
		Image:        c.Image,
		Version:      c.Version,
		Runtime:      c.Runtime,
		Driver:       c.Driver,
		PID:          c.PID,
		ExitCode:     c.ExitCode,
		Status:       c.Status,
		IsAttached:   c.IsAttached,
		Path:         c.Path,
		Cwd:          c.Cwd,
		CreatedAt:    c.CreatedAt,
		StartedAt:    c.StartedAt,
		FinishedAt:   c.FinishedAt,
		Mounts:       mounts,
		NetworkMode:  c.NetworkMode,
		CgroupnsMode: c.CgroupnsMode,
		IpcMode:      c.IpcMode,
		PidMode:      c.PidMode,
		UsernsMode:   c.UsernsMode,
		UTSMode:      c.UTSMode,
		Env:          append([]string(nil), c.Env...),
		Cmd:          append([]string(nil), c.Cmd...),
		Namespaces:   c.Namespaces,
	}
}

func (c Container) IsZero() bool {
	return c.ID == "" &&
		c.Name == "" &&
		c.HostName == "" &&
		c.ImageID == "" &&
		c.Image == "" &&
		c.Version == "" &&
		c.Runtime == "" &&
		c.Driver == "" &&
		c.PID == 0 &&
		c.ExitCode == 0 &&
		c.Status == "" &&
		!c.IsAttached &&
		c.Path == "" &&
		c.Cwd == "" &&
		c.CreatedAt.IsZero() &&
		c.StartedAt.IsZero() &&
		c.FinishedAt.IsZero() &&
		len(c.Mounts) == 0 &&
		c.NetworkMode == "" &&
		c.CgroupnsMode == "" &&
		c.IpcMode == "" &&
		c.PidMode == "" &&
		c.UsernsMode == "" &&
		c.UTSMode == "" &&
		len(c.Env) == 0 &&
		len(c.Cmd) == 0 &&
		c.Namespaces.IsZero()
}

func (c Container) MarshalJSON() ([]byte, error) {
	if c.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		ID           string      `json:"id"`
		Name         string      `json:"name,omitempty"`
		HostName     string      `json:"hostname,omitempty"`
		ImageID      string      `json:"image_id,omitempty"`
		Image        string      `json:"image,omitempty"`
		Version      string      `json:"version,omitempty"`
		Runtime      string      `json:"runtime,omitempty"`
		Driver       string      `json:"driver,omitempty"`
		PID          int         `json:"pid,omitempty"`
		ExitCode     int         `json:"exit_code,omitempty"`
		Status       string      `json:"status,omitempty"`
		IsAttached   bool        `json:"is_attached,omitempty"`
		Path         string      `json:"path,omitempty"`
		Cwd          string      `json:"cwd,omitempty"`
		CreatedAt    *time.Time  `json:"created_at,omitempty"`
		StartedAt    *time.Time  `json:"started_at,omitempty"`
		FinishedAt   *time.Time  `json:"finished_at,omitempty"`
		Mounts       []Mount     `json:"mounts,omitempty"`
		NetworkMode  string      `json:"network_mode,omitempty"`
		CgroupnsMode string      `json:"cgroupns_mode,omitempty"`
		IpcMode      string      `json:"ipc_mode,omitempty"`
		PidMode      string      `json:"pid_mode,omitempty"`
		UsernsMode   string      `json:"userns_mode,omitempty"`
		UTSMode      string      `json:"uts_mode,omitempty"`
		Env          []string    `json:"env,omitempty"`
		Cmd          []string    `json:"cmd,omitempty"`
		Namespaces   *Namespaces `json:"namespaces,omitempty"`
	}{
		ID:           c.ID,
		Name:         c.Name,
		HostName:     c.HostName,
		ImageID:      c.ImageID,
		Image:        c.Image,
		Version:      c.Version,
		Runtime:      c.Runtime,
		Driver:       c.Driver,
		PID:          c.PID,
		ExitCode:     c.ExitCode,
		Status:       c.Status,
		IsAttached:   c.IsAttached,
		Path:         c.Path,
		Cwd:          c.Cwd,
		Mounts:       c.Mounts,
		NetworkMode:  c.NetworkMode,
		CgroupnsMode: c.CgroupnsMode,
		IpcMode:      c.IpcMode,
		PidMode:      c.PidMode,
		UsernsMode:   c.UsernsMode,
		UTSMode:      c.UTSMode,
		Env:          c.Env,
		Cmd:          c.Cmd,
	}

	if !c.CreatedAt.IsZero() {
		created.CreatedAt = &c.CreatedAt
	}
	if !c.StartedAt.IsZero() {
		created.StartedAt = &c.StartedAt
	}
	if !c.FinishedAt.IsZero() {
		created.FinishedAt = &c.FinishedAt
	}
	if !c.Namespaces.IsZero() {
		created.Namespaces = &c.Namespaces
	}

	return json.Marshal(created)
}

//
// Profiling event.
//

// ProcessTree.

type ProcessTree struct {
	Process  string   `json:"process"`
	Ancestry []string `json:"ancestry"`
}

func (pt ProcessTree) Clone() ProcessTree {
	return ProcessTree{
		Process:  pt.Process,
		Ancestry: append([]string(nil), pt.Ancestry...),
	}
}

func (pt ProcessTree) IsZero() bool {
	return pt.Process == "" &&
		len(pt.Ancestry) == 0
}

func (pt ProcessTree) MarshalJSON() ([]byte, error) {
	if pt.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Process  string   `json:"process,omitempty"`
		Ancestry []string `json:"ancestry,omitempty"`
	}{
		Process:  pt.Process,
		Ancestry: pt.Ancestry,
	})
}

func (pt ProcessTree) String() string {
	if pt.IsZero() {
		return ""
	}
	ancestry := pt.StringSlice()
	return strings.Join(ancestry, "|")
}

func (pt ProcessTree) StringSlice() []string {
	if pt.IsZero() {
		return []string{}
	}
	ancestry := make([]string, 0, len(pt.Ancestry))
	for _, p := range pt.Ancestry {
		if p == "" {
			continue
		}
		ancestry = append(ancestry, p)
	}
	return ancestry
}

// GeoIP location type.

type GeoIPLocation struct {
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
	Continent     string  `json:"continent"`
	ContinentCode string  `json:"continent_code"`
	Country       string  `json:"country"`
	CountryCode   string  `json:"country_code"`
	Region        string  `json:"region"`
	RegionName    string  `json:"region_name"`
	City          string  `json:"city"`
	ISP           string  `json:"isp"`
	Org           string  `json:"org"`
	Asname        string  `json:"asname"`
}

func (gl GeoIPLocation) Clone() GeoIPLocation {
	return GeoIPLocation{
		Latitude:      gl.Latitude,
		Longitude:     gl.Longitude,
		Continent:     gl.Continent,
		ContinentCode: gl.ContinentCode,
		Country:       gl.Country,
		CountryCode:   gl.CountryCode,
		Region:        gl.Region,
		RegionName:    gl.RegionName,
		City:          gl.City,
		ISP:           gl.ISP,
		Org:           gl.Org,
		Asname:        gl.Asname,
	}
}

func (gl GeoIPLocation) IsZero() bool {
	return gl.Latitude == 0 &&
		gl.Longitude == 0 &&
		gl.Continent == "" &&
		gl.ContinentCode == "" &&
		gl.Country == "" &&
		gl.CountryCode == "" &&
		gl.Region == "" &&
		gl.RegionName == "" &&
		gl.City == "" &&
		gl.ISP == "" &&
		gl.Org == "" &&
		gl.Asname == ""
}

func (gl GeoIPLocation) MarshalJSON() ([]byte, error) {
	if gl.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Latitude      float64 `json:"latitude,omitempty"`
		Longitude     float64 `json:"longitude,omitempty"`
		Continent     string  `json:"continent,omitempty"`
		ContinentCode string  `json:"continent_code,omitempty"`
		Country       string  `json:"country,omitempty"`
		CountryCode   string  `json:"country_code,omitempty"`
		Region        string  `json:"region,omitempty"`
		RegionName    string  `json:"region_name,omitempty"`
		City          string  `json:"city,omitempty"`
		ISP           string  `json:"isp,omitempty"`
		Org           string  `json:"org,omitempty"`
		Asname        string  `json:"asname,omitempty"`
	}{
		Latitude:      gl.Latitude,
		Longitude:     gl.Longitude,
		Continent:     gl.Continent,
		ContinentCode: gl.ContinentCode,
		Country:       gl.Country,
		CountryCode:   gl.CountryCode,
		Region:        gl.Region,
		RegionName:    gl.RegionName,
		City:          gl.City,
		ISP:           gl.ISP,
		Org:           gl.Org,
		Asname:        gl.Asname,
	})
}

func (gl GeoIPLocation) String() string {
	if gl.IsZero() {
		return ""
	}
	return strings.Join([]string{
		fmt.Sprintf("%f", gl.Latitude),
		fmt.Sprintf("%f", gl.Longitude),
		gl.Continent,
		gl.ContinentCode,
		gl.Country,
		gl.CountryCode,
		gl.Region,
		gl.RegionName,
		gl.City,
		gl.ISP,
		gl.Org,
		gl.Asname,
	}, ", ")
}

// Egress Peer: A single remote peer that supports the egress profile.

type Peer struct {
	Result        Result        `json:"result"`
	Detections    []string      `json:"detections"`
	Protocol      string        `json:"protocol"`
	LocalAddress  string        `json:"local_address"`
	RemoteAddress string        `json:"remote_address"`
	LocalNames    []string      `json:"local_names"`
	RemoteNames   []string      `json:"remote_names"`
	RemotePorts   []string      `json:"remote_ports"`
	ProcTrees     []ProcessTree `json:"proc_trees"`
	RemoteGeoInfo GeoIPLocation `json:"remote_geo_info"`
}

func (ep Peer) Clone() Peer {
	processTrees := make([]ProcessTree, len(ep.ProcTrees))
	for i, tree := range ep.ProcTrees {
		processTrees[i] = tree.Clone()
	}
	return Peer{
		Result:        ep.Result,
		Detections:    append([]string(nil), ep.Detections...),
		Protocol:      ep.Protocol,
		LocalAddress:  ep.LocalAddress,
		LocalNames:    append([]string(nil), ep.LocalNames...),
		RemoteAddress: ep.RemoteAddress,
		RemoteNames:   append([]string(nil), ep.RemoteNames...),
		RemotePorts:   append([]string(nil), ep.RemotePorts...),
		ProcTrees:     processTrees,
		RemoteGeoInfo: ep.RemoteGeoInfo,
	}
}

func (ep Peer) IsZero() bool {
	return ep.Result.IsZero() &&
		len(ep.Detections) == 0 &&
		ep.Protocol == "" &&
		ep.LocalAddress == "" &&
		ep.RemoteAddress == "" &&
		len(ep.LocalNames) == 0 &&
		len(ep.RemoteNames) == 0 &&
		len(ep.RemotePorts) == 0 &&
		len(ep.ProcTrees) == 0 &&
		ep.RemoteGeoInfo.IsZero()
}

func (ep Peer) MarshalJSON() ([]byte, error) {
	if ep.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		Result        string         `json:"result"`
		Detections    []string       `json:"detections"`
		Protocol      string         `json:"protocol"`
		LocalAddress  string         `json:"local_address"`
		RemoteAddress string         `json:"remote_address"`
		LocalNames    []string       `json:"local_names,omitempty"`
		RemoteNames   []string       `json:"remote_names,omitempty"`
		RemotePorts   []string       `json:"remote_ports,omitempty"`
		ProcTrees     []ProcessTree  `json:"proc_trees,omitempty"`
		RemoteGeoInfo *GeoIPLocation `json:"remote_geo_info,omitempty"`
	}{
		Result:        ep.Result.String(),
		Detections:    ep.Detections,
		Protocol:      ep.Protocol,
		LocalAddress:  ep.LocalAddress,
		RemoteAddress: ep.RemoteAddress,
		LocalNames:    ep.LocalNames,
		RemoteNames:   ep.RemoteNames,
		RemotePorts:   ep.RemotePorts,
		ProcTrees:     ep.ProcTrees,
	}

	if !ep.RemoteGeoInfo.IsZero() {
		created.RemoteGeoInfo = &ep.RemoteGeoInfo
	}

	return json.Marshal(created)
}

func (ep Peer) String() string {
	return strings.Join([]string{
		ep.Protocol,
		ep.LocalAddress,
		ep.RemoteAddress,
	}, "|")
}

// Direction: Ingress, Egress or Local traffic.

type Direction struct {
	Peers   []Peer   `json:"peers"`
	Domains []string `json:"domains"`
}

func (e Direction) Clone() Direction {
	peers := make([]Peer, len(e.Peers))
	for i, ep := range e.Peers {
		peers[i] = ep.Clone()
	}
	return Direction{
		Peers:   peers,
		Domains: append([]string(nil), e.Domains...),
	}
}

func (e Direction) IsZero() bool {
	return len(e.Peers) == 0 &&
		len(e.Domains) == 0
}

func (e Direction) MarshalJSON() ([]byte, error) {
	if e.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Peers   []Peer   `json:"peers,omitempty"`
		Domains []string `json:"domains,omitempty"`
	}{
		Peers:   e.Peers,
		Domains: e.Domains,
	})
}

// NetProfile: A collection of network telemetry that supports the profile.

type NetProfile struct {
	Egress  Direction `json:"egress"`
	Ingress Direction `json:"ingress"`
	Local   Direction `json:"local"`
}

func (np NetProfile) Clone() NetProfile {
	return NetProfile{
		Egress:  np.Egress.Clone(),
		Ingress: np.Ingress.Clone(),
		Local:   np.Local.Clone(),
	}
}

func (np NetProfile) IsZero() bool {
	return np.Egress.IsZero() &&
		np.Ingress.IsZero() &&
		np.Local.IsZero()
}

func (np NetProfile) MarshalJSON() ([]byte, error) {
	if np.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		Egress  *Direction `json:"egress,omitempty"`
		Ingress *Direction `json:"ingress,omitempty"`
		Local   *Direction `json:"local,omitempty"`
	}{}

	if !np.Egress.IsZero() {
		created.Egress = &np.Egress
	}
	if !np.Ingress.IsZero() {
		created.Ingress = &np.Ingress
	}
	if !np.Local.IsZero() {
		created.Local = &np.Local
	}

	return json.Marshal(created)
}

// DirectionNetTelemetry: Summary of network telemetry for a direction.

type DirectionNetTelemetry struct {
	TotalDomains     uint `json:"total_domains"`
	TotalConnections uint `json:"total_connections"`
}

func (int DirectionNetTelemetry) Clone() DirectionNetTelemetry {
	return DirectionNetTelemetry{
		TotalDomains:     int.TotalDomains,
		TotalConnections: int.TotalConnections,
	}
}

func (int DirectionNetTelemetry) IsZero() bool {
	// Both values must be zero to be considered zero.
	return false
}

func (int DirectionNetTelemetry) MarshalJSON() ([]byte, error) {
	if int.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		TotalDomains     uint `json:"total_domains"`
		TotalConnections uint `json:"total_connections"`
	}{
		TotalDomains:     int.TotalDomains,
		TotalConnections: int.TotalConnections,
	})
}

// NetTelemetry: Summary of network telemetry for the profile.

type NetTelemetry struct {
	Egress  DirectionNetTelemetry `json:"egress"`
	Ingress DirectionNetTelemetry `json:"ingress"`
	Local   DirectionNetTelemetry `json:"local"`
}

func (nt NetTelemetry) Clone() NetTelemetry {
	return NetTelemetry{
		Egress:  nt.Egress.Clone(),
		Ingress: nt.Ingress.Clone(),
		Local:   nt.Local.Clone(),
	}
}

func (nt NetTelemetry) IsZero() bool {
	return nt.Egress.IsZero() && nt.Ingress.IsZero() && nt.Local.IsZero()
}

func (nt NetTelemetry) MarshalJSON() ([]byte, error) {
	if nt.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		Egress  *DirectionNetTelemetry `json:"egress,omitempty"`
		Ingress *DirectionNetTelemetry `json:"ingress,omitempty"`
		Local   *DirectionNetTelemetry `json:"local,omitempty"`
	}{}

	if !nt.Egress.IsZero() {
		created.Egress = &nt.Egress
	}
	if !nt.Ingress.IsZero() {
		created.Ingress = &nt.Ingress
	}
	if !nt.Local.IsZero() {
		created.Local = &nt.Local
	}

	return json.Marshal(created)
}

// Telemetry: A collection of telemetry data that supports the profile.

type Telemetry struct {
	Network NetTelemetry `json:"network"`
}

func (t Telemetry) Clone() Telemetry {
	return Telemetry{
		Network: t.Network.Clone(),
	}
}

func (t Telemetry) IsZero() bool {
	return t.Network.IsZero()
}

func (t Telemetry) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Network NetTelemetry `json:"network"`
	}{
		Network: t.Network,
	})
}

// Evidence: A single piece of evidence that supports an assertion.

type Evidence struct {
	Timestamp time.Time `json:"timestamp"`  // Event timestamp.
	EventName string    `json:"event_name"` // Event name.
	Peer      Peer      `json:"peer"`       // Peer.
}

func (e Evidence) Clone() Evidence {
	return Evidence{
		Timestamp: e.Timestamp,
		EventName: e.EventName,
		Peer:      e.Peer.Clone(),
	}
}

func (e Evidence) IsZero() bool {
	return e.Timestamp.IsZero() &&
		e.EventName == "" &&
		e.Peer.IsZero()
}

func (e Evidence) MarshalJSON() ([]byte, error) {
	if e.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		Timestamp time.Time `json:"timestamp"`
		EventName string    `json:"event_name"`
		Peer      *Peer     `json:"peer,omitempty"`
	}{
		Timestamp: e.Timestamp,
		EventName: e.EventName,
	}

	if !e.Peer.IsZero() {
		created.Peer = &e.Peer
	}

	return json.Marshal(created)
}

// ResultID: A unique identifier for a result.

type ResultID uint64

const (
	ResultIDNone            ResultID = 0
	ResultNoBadEgressDomain ResultID = 1 << (iota - 1)
	ResultNoBadIngressDomain
	ResultNoBadLocalDomain
	ResultIDMax
)

var resultIDStrings = map[ResultID]string{
	ResultIDNone:             "",
	ResultNoBadEgressDomain:  "no_bad_egress_domain",
	ResultNoBadIngressDomain: "no_bad_ingress_domain",
	ResultNoBadLocalDomain:   "no_bad_local_domain",
}

func (rid ResultID) IsZero() bool {
	return rid == ResultIDNone
}

func (rid ResultID) String() string {
	if rid == ResultIDNone {
		return ""
	}

	var parts []string
	for id, name := range resultIDStrings {
		if id == ResultIDNone {
			continue
		}
		if rid&id != 0 {
			parts = append(parts, name)
		}
	}

	if len(parts) == 0 {
		return resultIDStrings[ResultIDNone]
	}

	return strings.Join(parts, "|")
}

func (rid ResultID) StringSlice() []string {
	if rid == ResultIDNone {
		return []string{}
	}

	var parts []string
	for id, name := range resultIDStrings {
		if id == ResultIDNone {
			continue
		}
		if rid&id != 0 {
			parts = append(parts, name)
		}
	}

	return parts
}

func (rid *ResultID) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*rid = ResultIDNone
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s == "" {
			*rid = ResultIDNone
			return nil
		}

		parts := strings.Split(s, "|")
		var result ResultID
		for _, part := range parts {
			name := strings.TrimSpace(part)
			if name == "" {
				continue
			}

			matched := false
			for id, idName := range resultIDStrings {
				if id == ResultIDNone {
					continue
				}
				if idName == name {
					result |= id
					matched = true
					break
				}
			}

			if !matched {
				return fmt.Errorf("invalid result id: %s", name)
			}
		}

		*rid = result
		return nil
	}

	var n uint64
	if err := json.Unmarshal(data, &n); err == nil {
		*rid = ResultID(n)
		return nil
	}

	return fmt.Errorf("invalid result id payload: %s", string(data))
}

// Result: A result of an assertion.

type Result uint

const (
	ResultNone Result = 0
	ResultGood Result = 1 << iota
	ResultAttention
	ResultBad
)

var resultStrings = map[Result]string{
	ResultNone:      "",
	ResultGood:      "pass",
	ResultAttention: "attention",
	ResultBad:       "fail",
}

func (r Result) IsGood() bool {
	return r&ResultGood != 0
}

func (r Result) IsAttention() bool {
	return r&ResultAttention != 0
}

func (r Result) IsBad() bool {
	return r&ResultBad != 0
}

func (r Result) IsZero() bool {
	return r == ResultNone
}

func (r Result) String() string {
	if r == ResultNone {
		return ""
	}

	var parts []string
	for id, name := range resultStrings {
		if id == ResultNone {
			continue
		}
		if r&id != 0 {
			parts = append(parts, name)
		}
	}

	if len(parts) == 0 {
		return resultStrings[ResultNone]
	}

	return strings.Join(parts, "|")
}

func (r Result) StringSlice() []string {
	if r == ResultNone {
		return []string{}
	}

	var parts []string
	for id, name := range resultStrings {
		if id == ResultNone {
			continue
		}
		if r&id != 0 {
			parts = append(parts, name)
		}
	}

	return parts
}

func (r Result) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func (r *Result) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*r = ResultNone
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s == "" {
			*r = ResultNone
			return nil
		}

		parts := strings.Split(s, "|")
		var result Result
		for _, part := range parts {
			name := strings.TrimSpace(part)
			if name == "" {
				continue
			}

			matched := false
			for id, resultName := range resultStrings {
				if id == ResultNone {
					continue
				}
				if resultName == name {
					result |= id
					matched = true
					break
				}
			}

			if !matched {
				return fmt.Errorf("invalid result: %s", name)
			}
		}

		*r = result
		return nil
	}

	var n uint
	if err := json.Unmarshal(data, &n); err == nil {
		*r = Result(n)
		return nil
	}

	return fmt.Errorf("invalid result payload: %s", string(data))
}

func (r Result) Number() int {
	return int(r)
}

// Assertion: A list of evidence that supports the assertion.

type Assertion struct {
	Result   Result     `json:"result"`   // Result of the assertion.
	ResultID ResultID   `json:"id"`       // Result ID.
	Evidence []Evidence `json:"evidence"` // Detections supporting the result.
}

func (a Assertion) Clone() Assertion {
	evidence := make([]Evidence, len(a.Evidence))
	for i, e := range a.Evidence {
		evidence[i] = e.Clone()
	}
	return Assertion{
		Result:   a.Result,
		ResultID: a.ResultID,
		Evidence: evidence,
	}
}

func (a Assertion) IsZero() bool {
	return a.Result.IsZero() &&
		a.ResultID.IsZero() &&
		len(a.Evidence) == 0
}

func (a Assertion) MarshalJSON() ([]byte, error) {
	if a.IsZero() {
		return []byte("null"), nil
	}

	result := ResultGood.String()
	if !a.Result.IsZero() {
		result = a.Result.String()
	}

	id := ResultNoBadEgressDomain.String()
	if !a.ResultID.IsZero() {
		id = a.ResultID.String()
	}

	return json.Marshal(struct {
		Result   string     `json:"result"`
		ResultID string     `json:"id"`
		Evidence []Evidence `json:"evidence,omitempty"`
	}{
		Result:   result,
		ResultID: id,
		Evidence: a.Evidence,
	})
}

// Behavior Profile Event.

type Profile struct {
	Base
	Network    NetProfile  `json:"network"`
	Telemetry  Telemetry   `json:"telemetry"`
	Assertions []Assertion `json:"assertions"`
}

func (p Profile) Clone() Profile {
	assertions := make([]Assertion, len(p.Assertions))
	for i, a := range p.Assertions {
		assertions[i] = a.Clone()
	}
	return Profile{
		Base:       p.Base.Clone(),
		Network:    p.Network.Clone(),
		Telemetry:  p.Telemetry.Clone(),
		Assertions: assertions,
	}
}

func (p Profile) IsZero() bool {
	return p.Base.IsZero() &&
		p.Network.IsZero() &&
		p.Telemetry.IsZero() &&
		len(p.Assertions) == 0
}

func (p Profile) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		UUID       *string     `json:"uuid,omitempty"`
		Timestamp  *time.Time  `json:"timestamp,omitempty"`
		Note       *string     `json:"note,omitempty"`
		Metadata   *Metadata   `json:"metadata,omitempty"`
		Attenuator *Attenuator `json:"attenuator,omitempty"`
		Score      *Score      `json:"score,omitempty"`
		Background *Background `json:"background,omitempty"`
		Scenarios  *Scenarios  `json:"scenarios,omitempty"`
		Network    *NetProfile `json:"network,omitempty"`
		Telemetry  *Telemetry  `json:"telemetry,omitempty"`
		Assertions []Assertion `json:"assertions,omitempty"`
	}{}

	if !p.Base.IsZero() {
		created.UUID = &p.UUID
		created.Timestamp = &p.Timestamp

		if p.Note != "" {
			created.Note = &p.Note
		}
		if !p.Metadata.IsZero() {
			created.Metadata = &p.Metadata
		}
		if !p.Attenuator.IsZero() {
			created.Attenuator = &p.Attenuator
		}
		if !p.Score.IsZero() {
			created.Score = &p.Score
		}
		if !p.Background.IsZero() {
			created.Background = &p.Background
		}
		if !p.Scenarios.IsZero() {
			created.Scenarios = &p.Scenarios
		}
	}

	if !p.Network.IsZero() {
		created.Network = &p.Network
	}
	if !p.Telemetry.IsZero() {
		created.Telemetry = &p.Telemetry
	}
	if len(p.Assertions) > 0 {
		created.Assertions = p.Assertions
	}

	return json.Marshal(created)
}
