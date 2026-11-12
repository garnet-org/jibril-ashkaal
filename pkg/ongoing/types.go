package ongoing

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// All detection events have these fields.

type Base struct {
	UUID       string     `json:"uuid,omitempty" desc:"The unique ID of the event."`             // The unique ID of the event.
	Timestamp  time.Time  `json:"timestamp,omitzero" desc:"The timestamp of the event."`         // The timestamp of the event.
	Note       string     `json:"note,omitempty" desc:"A note about the event."`                 // A note about the event.
	Metadata   Metadata   `json:"metadata,omitzero" desc:"The event metadata."`                  // The event metadata.
	Attenuator Attenuator `json:"attenuator,omitzero" desc:"The attenuator of the event."`       // The attenuator of the event.
	Score      Score      `json:"score,omitzero" desc:"Event security risk score."`              // Event Security Risk Score.
	Background Background `json:"background,omitzero" desc:"The event context."`                 // The event context.
	Scenarios  Scenarios  `json:"scenarios,omitzero" desc:"Environment scenarios of the event."` // GitHub, Kubernetes, Host, etc.
}

var legacyTimeLayouts = [...]string{
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
}

// legacyTime is a wrapper around time.Time to support multiple legacy time formats during JSON unmarshaling.
// It is here because older types used to use string instead of time.Time for timestamps.
// It also treats legacy sentinel values like "running" as an empty timestamp.
type legacyTime struct {
	time.Time
}

func (lt *legacyTime) UnmarshalJSON(data []byte) error {
	parsed, err := parseLegacyTime(data)
	if err != nil {
		return err
	}

	lt.Time = parsed

	return nil
}

func parseLegacyTime(data []byte) (time.Time, error) {
	if string(data) == "null" {
		return time.Time{}, nil
	}

	var parsed time.Time
	if err := json.Unmarshal(data, &parsed); err == nil {
		return parsed, nil
	}

	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return time.Time{}, fmt.Errorf("invalid time payload: %s", string(data))
	}

	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "running") {
		return time.Time{}, nil
	}

	for _, layout := range legacyTimeLayouts {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed, nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid time value: %q", value)
}

type baseAlias Base

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

func (b *Base) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*b = Base{}
		return nil
	}

	type basePayload struct {
		baseAlias
		Timestamp legacyTime `json:"timestamp"`
	}

	var decoded basePayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*b = Base(decoded.baseAlias)
	b.Timestamp = decoded.Timestamp.Time

	return nil
}

// Detection Event Metadata.

type Metadata struct {
	Kind          string `json:"kind" desc:"Detection event class name."`                           // Detection event class name.
	Name          string `json:"name" desc:"Detection recipe name."`                                // Detection recipe name.
	Format        string `json:"format" desc:"Detection event format."`                             // Detection event format.
	Version       string `json:"version" desc:"Detection event format version."`                    // Detection event format version.
	Description   string `json:"description,omitempty" desc:"Detection event description."`         // Detection event description.
	Tactic        string `json:"tactic,omitempty" desc:"Detection event MITRE tactic."`             // Detection event MITRE tactic.
	Technique     string `json:"technique,omitempty" desc:"Detection event MITRE technique."`       // Detection event MITRE technique.
	SubTechnique  string `json:"subtechnique,omitempty" desc:"Detection event MITRE subtechnique."` // Detection event MITRE subtechnique.
	Importance    string `json:"importance,omitempty" desc:"Detection event importance."`           // Detection event importance.
	Documentation string `json:"documentation,omitempty" desc:"Detection event documentation."`     // Detection event documentation.
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
	Source        string   `json:"source" desc:"Source of the score."`                                                             // Source of the score.
	Severity      int      `json:"severity" desc:"Severity number of the detection (0-100)."`                                      // Severity number of the detection (0-100).
	SeverityLevel string   `json:"severity_level" desc:"Severity level of the detection (none, low, medium, high, critical)."`     // Severity level of the detection (none, low, medium, high, critical).
	Confidence    float64  `json:"confidence" desc:"Confidence percentage of the detection (0.0-1.0)."`                            // Confidence percentage of the detection (0.0-1.0).
	RiskScore     float64  `json:"risk_score,omitempty" desc:"Calculated and rounded up risk score of the detection (0.0-100.0)."` // Calculated and rounded up risk score of the detection (0.0-100.0).
	Reasons       []string `json:"reasons,omitempty" desc:"Reasons explaining why this score was assigned."`                       // Reasons to explain to users why this score.
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
	AttenuatedBy     string  `json:"attenuated_by" desc:"The model that attenuated the detection."`                                               // The model that attenuated the detection.
	Interpretation   string  `json:"interpretation" desc:"The interpretation of the attenuation."`                                                // The interpretation of the attenuation.
	Thinking         string  `json:"thinking,omitempty" desc:"The thinking process of the attenuation."`                                          // The thinking of the attenuation.
	IsFalsePositive  bool    `json:"is_false_positive" desc:"Whether the detection is a false positive."`                                         // Whether the detection is a false positive.
	NewSeverity      int     `json:"new_severity" desc:"The new detection severity after attenuation (0-100)."`                                   // The new detection severity after attenuation (0-100).
	NewSeverityLevel string  `json:"new_severity_level" desc:"The new detection severity level after attenuation (low, medium, high, critical)."` // The new detection severity level after attenuation (low, medium, high, critical).
	NewConfidence    float64 `json:"new_confidence" desc:"The new detection confidence after attenuation (0.0-1.0)."`                             // The new detection confidence after attenuation (0.0-1.0).
	NewRiskScore     float64 `json:"new_risk_score" desc:"The new detection risk score after attenuation (0.0-100.0)."`                           // The new detection risk score after attenuation (0.0-100.0).
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
	Containers  Containers    `json:"containers,omitzero" desc:"Containers and namespaces associated with the event."`
	Files       []File        `json:"file_list,omitempty" desc:"Files associated with the event."`
	Flows       []Flow        `json:"flow_list,omitempty" desc:"Network flows associated with the event."`
	Ancestry    []Process     `json:"ancestry,omitempty" desc:"Process ancestry chain associated with the event."`
	LegacyFiles FileAggregate `json:"files,omitzero" desc:"Legacy aggregated file tree associated with the event."`     // TODO: Remove this field.
	LegacyFlows FlowAggregate `json:"flows,omitzero" desc:"Legacy aggregated network flows associated with the event."` // TODO: Remove this field.
}

func (b Background) Clone() Background {
	// Filter non-zero ancestry.
	ancestry := make([]Process, 0, len(b.Ancestry))
	for _, p := range b.Ancestry {
		if !p.IsZero() {
			ancestry = append(ancestry, p)
		}
	}

	// Filter non-zero files.
	files := make([]File, 0, len(b.Files))
	for _, f := range b.Files {
		if !f.IsZero() {
			files = append(files, f)
		}
	}

	// Filter non-zero flows.
	flows := make([]Flow, 0, len(b.Flows))
	for _, fl := range b.Flows {
		if !fl.IsZero() {
			flows = append(flows, fl)
		}
	}

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
	// Filter non-zero files.
	filesNonZero := false
	for _, f := range b.Files {
		if !f.IsZero() {
			filesNonZero = true
			break
		}
	}

	// Filter non-zero flows.
	flowsNonZero := false
	for _, fl := range b.Flows {
		if !fl.IsZero() {
			flowsNonZero = true
			break
		}
	}

	// Filter non-zero ancestry.
	ancestryNonZero := false
	for _, p := range b.Ancestry {
		if !p.IsZero() {
			ancestryNonZero = true
			break
		}
	}

	return b.Containers.IsZero() &&
		!filesNonZero &&
		!flowsNonZero &&
		!ancestryNonZero &&
		b.LegacyFiles.IsZero() &&
		b.LegacyFlows.IsZero()
}

func (b Background) MarshalJSON() ([]byte, error) {
	// Filter non-zero files.
	filteredFiles := make([]File, 0, len(b.Files))
	for _, f := range b.Files {
		if !f.IsZero() {
			filteredFiles = append(filteredFiles, f)
		}
	}

	// Filter non-zero flows.
	filteredFlows := make([]Flow, 0, len(b.Flows))
	for _, fl := range b.Flows {
		if !fl.IsZero() {
			filteredFlows = append(filteredFlows, fl)
		}
	}

	// Filter non-zero ancestry.
	filteredAncestry := make([]Process, 0, len(b.Ancestry))
	for _, p := range b.Ancestry {
		if !p.IsZero() {
			filteredAncestry = append(filteredAncestry, p)
		}
	}

	hasFiles := len(filteredFiles) > 0
	hasFlows := len(filteredFlows) > 0
	hasAncestry := len(filteredAncestry) > 0
	hasLegacyFiles := !b.LegacyFiles.IsZero()
	hasLegacyFlows := !b.LegacyFlows.IsZero()
	hasContainers := !b.Containers.IsZero() && len(b.Containers.Containers) > 0

	if !hasContainers && !hasFiles && !hasFlows &&
		!hasAncestry && !hasLegacyFiles && !hasLegacyFlows {
		return []byte("null"), nil
	}

	created := struct {
		Containers  *Containers    `json:"containers,omitempty"`
		Files       []File         `json:"file_list,omitempty"`
		Flows       []Flow         `json:"flow_list,omitempty"`
		Ancestry    []Process      `json:"ancestry,omitempty"`
		LegacyFiles *FileAggregate `json:"files,omitempty"`
		LegacyFlows *FlowAggregate `json:"flows,omitempty"`
	}{}

	if hasContainers {
		created.Containers = &b.Containers
	}
	if hasFiles {
		created.Files = filteredFiles
	}
	if hasFlows {
		created.Flows = filteredFlows
	}
	if hasAncestry {
		created.Ancestry = filteredAncestry
	}
	if hasLegacyFiles {
		created.LegacyFiles = &b.LegacyFiles
	}
	if hasLegacyFlows {
		created.LegacyFlows = &b.LegacyFlows
	}

	return json.Marshal(created)
}

// File Access Detection Event.

type FileAccess struct {
	Base
	File    File    `json:"file,omitzero" desc:"File accessed by the process."`      // File accessed by the process.
	Process Process `json:"process,omitzero" desc:"Process that accessed the file."` // Process that accessed the file.
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

func (f *FileAccess) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*f = FileAccess{}
		return nil
	}

	var decoded struct {
		baseAlias
		Timestamp legacyTime `json:"timestamp"`
		File      File       `json:"file"`
		Process   Process    `json:"process"`
	}

	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*f = FileAccess{
		Base:    Base(decoded.baseAlias),
		File:    decoded.File,
		Process: decoded.Process,
	}
	f.Timestamp = decoded.Timestamp.Time

	return nil
}

// Execution Detection Event.

type Execution struct {
	Base
	File    File    `json:"file,omitzero" desc:"Executed file."`
	Process Process `json:"process,omitzero" desc:"Executed process."`
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

func (e *Execution) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*e = Execution{}
		return nil
	}

	var decoded struct {
		baseAlias
		Timestamp legacyTime `json:"timestamp"`
		File      File       `json:"file"`
		Process   Process    `json:"process"`
	}

	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*e = Execution{
		Base:    Base(decoded.baseAlias),
		File:    decoded.File,
		Process: decoded.Process,
	}
	e.Timestamp = decoded.Timestamp.Time

	return nil
}

// Network Peers Detection Event.

type NetworkPeer struct {
	Base
	Process Process `json:"process,omitzero" desc:"Process triggering the detection with the flow."` // Process triggering the detection with the flow.
	Flow    Flow    `json:"flow,omitzero" desc:"Network flow triggering the detection."`             // Network flow triggering the detection.
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

func (n *NetworkPeer) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*n = NetworkPeer{}
		return nil
	}

	var decoded struct {
		baseAlias
		Timestamp legacyTime `json:"timestamp"`
		Process   Process    `json:"process"`
		Flow      Flow       `json:"flow"`
	}

	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*n = NetworkPeer{
		Base:    Base(decoded.baseAlias),
		Process: decoded.Process,
		Flow:    decoded.Flow,
	}
	n.Timestamp = decoded.Timestamp.Time

	return nil
}

// Network Flow Event.

type NetworkFlow struct {
	Base
	Process Process `json:"process,omitzero" desc:"Process associated with the network flow."`
	Flow    Flow    `json:"flow,omitzero" desc:"Network flow."`
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

func (n *NetworkFlow) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*n = NetworkFlow{}
		return nil
	}

	var decoded struct {
		baseAlias
		Timestamp legacyTime `json:"timestamp"`
		Process   Process    `json:"process"`
		Flow      Flow       `json:"flow"`
	}

	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*n = NetworkFlow{
		Base:    Base(decoded.baseAlias),
		Process: decoded.Process,
		Flow:    decoded.Flow,
	}
	n.Timestamp = decoded.Timestamp.Time

	return nil
}

// Drop IP Detection Event.

type DropIP struct {
	Base
	IP      string   `json:"ip,omitempty" desc:"The IP address that was dropped."`     // The IP that was dropped.
	Names   []string `json:"names,omitempty" desc:"The domain names of the IP."`       // The names of the IP.
	Process Process  `json:"process,omitzero" desc:"Process that triggered the drop."` // Process that triggered the drop.
	Flow    Flow     `json:"flow,omitzero" desc:"The flow that triggered the drop."`   // The flow that triggered the drop.
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

func (d *DropIP) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*d = DropIP{}
		return nil
	}

	var decoded struct {
		baseAlias
		Timestamp legacyTime `json:"timestamp"`
		IP        string     `json:"ip"`
		Names     []string   `json:"names"`
		Process   Process    `json:"process"`
		Flow      Flow       `json:"flow"`
	}

	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*d = DropIP{
		Base:    Base(decoded.baseAlias),
		IP:      decoded.IP,
		Names:   decoded.Names,
		Process: decoded.Process,
		Flow:    decoded.Flow,
	}
	d.Timestamp = decoded.Timestamp.Time

	return nil
}

// Process.

type Process struct {
	UUID       string     `json:"uuid" desc:"Unique ID of the process."`                           // Unique ID of the process.
	Start      time.Time  `json:"start" desc:"The start time of the process."`                     // The start time of the process.
	Exit       time.Time  `json:"exit" desc:"The exit time of the process."`                       // The exit time of the process.
	Code       int        `json:"retcode" desc:"The return code of the process."`                  // The return code of the process.
	UID        uint       `json:"uid" desc:"The user ID of the process."`                          // The user ID of the process.
	Pid        int        `json:"pid" desc:"The process ID."`                                      // The process ID.
	Ppid       int        `json:"ppid" desc:"The parent process ID."`                              // The parent process ID.
	Comm       string     `json:"comm" desc:"The command name."`                                   // The command name.
	Cmd        string     `json:"cmd" desc:"The command line."`                                    // The command.
	Exe        string     `json:"exe" desc:"The executable path."`                                 // The executable name.
	Args       string     `json:"args,omitempty" desc:"The command arguments."`                    // The arguments.
	Envs       string     `json:"envs,omitempty" desc:"The environment variables."`                // The environment variables.
	Loader     string     `json:"loader,omitempty" desc:"The dynamic loader path."`                // The loader name.
	PrevExe    string     `json:"prev_exe,omitempty" desc:"The previous executable path."`         // The previous executable name.
	PrevArgs   string     `json:"prev_args,omitempty" desc:"The previous command arguments."`      // The previous arguments.
	PrevEnvs   string     `json:"prev_envs,omitempty" desc:"The previous environment variables."`  // The previous environment variables.
	PrevLoader string     `json:"prev_loader,omitempty" desc:"The previous dynamic loader path."`  // The previous loader name.
	Namespaces Namespaces `json:"namespaces,omitzero" desc:"The Linux namespaces of the process."` // The namespaces.
	// Hashes for external indexing amongst other ongoing events.
	ProcessHash    uint32 `json:"process_hash,omitempty" desc:"The hash of the process."`                          // The hash of the process.
	ParentHash     uint32 `json:"parent_hash,omitempty" desc:"The hash of the parent process."`                    // The hash of the parent process.
	CommHash       uint32 `json:"comm_hash,omitempty" desc:"The hash of the command."`                             // The hash of the command.
	ExeHash        uint32 `json:"exe_hash,omitempty" desc:"The hash of the executable."`                           // The hash of the executable.
	ArgsHash       uint32 `json:"args_hash,omitempty" desc:"The hash of the arguments."`                           // The hash of the arguments.
	EnvsHash       uint32 `json:"envs_hash,omitempty" desc:"The hash of the environment variables."`               // The hash of the environment variables.
	LoaderHash     uint32 `json:"loader_hash,omitempty" desc:"The hash of the loader."`                            // The hash of the loader.
	PrevExeHash    uint32 `json:"prev_exe_hash,omitempty" desc:"The hash of the previous executable."`             // The hash of the previous executable.
	PrevArgsHash   uint32 `json:"prev_args_hash,omitempty" desc:"The hash of the previous arguments."`             // The hash of the previous arguments.
	PrevEnvsHash   uint32 `json:"prev_envs_hash,omitempty" desc:"The hash of the previous environment variables."` // The hash of the previous environment variables.
	PrevLoaderHash uint32 `json:"prev_loader_hash,omitempty" desc:"The hash of the previous loader."`              // The hash of the previous loader.
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

func (p *Process) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*p = Process{}
		return nil
	}

	type processAlias Process

	var decoded struct {
		processAlias
		Start legacyTime `json:"start"`
		Exit  legacyTime `json:"exit"`
	}

	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*p = Process(decoded.processAlias)
	p.Start = decoded.Start.Time
	p.Exit = decoded.Exit.Time

	return nil
}

// Namespaces.

type Namespaces struct {
	MNTNs    uint32 `json:"mnt_ns,omitempty" desc:"Mount namespace inode ID."`     // Mount namespace.
	PIDNs    uint32 `json:"pid_ns,omitempty" desc:"PID namespace inode ID."`       // PID namespace.
	UTSNs    uint32 `json:"uts_ns,omitempty" desc:"UTS namespace inode ID."`       // UTS namespace.
	IPCNs    uint32 `json:"ipc_ns,omitempty" desc:"IPC namespace inode ID."`       // IPC namespace.
	NetNs    uint32 `json:"net_ns,omitempty" desc:"Network namespace inode ID."`   // Network namespace.
	CgroupNs uint32 `json:"cgroup_ns,omitempty" desc:"Cgroup namespace inode ID."` // Cgroup namespace.
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
	UUID        string          `json:"uuid" desc:"UUID of the file."`                                                  // UUID of the file.
	Path        string          `json:"path" desc:"Absolute path to the file."`                                         // Absolute path to the file.
	Dir         string          `json:"dir" desc:"Directory containing the file."`                                      // Directory containing the file.
	Base        string          `json:"basename" desc:"Base name of the file."`                                         // Base name of the file.
	Type        string          `json:"type" desc:"File type: regular, directory, symlink, socket, block, char, fifo."` // File type: regular, directory, symlink, socket, block, char, fifo.
	Owner       FileOwner       `json:"owner" desc:"File owner."`                                                       // File owner.
	Actions     FileActions     `json:"actions,omitzero" desc:"Detailed actions performed on the file."`                // Detailed actions performed on the file.
	Permissions FilePermissions `json:"permissions,omitzero" desc:"File permissions."`                                  // File permissions.
	Metadata    FileMetadata    `json:"metadata,omitzero" desc:"File metadata."`                                        // File metadata.
	// Hashes for external indexing amongst other ongoing events.
	FileHash uint32 `json:"file_hash,omitempty" desc:"The hash of the file."`      // The hash of the file.
	DirHash  uint32 `json:"dir_hash,omitempty" desc:"The hash of the directory."`  // The hash of the directory.
	BaseHash uint32 `json:"base_hash,omitempty" desc:"The hash of the base name."` // The hash of the base name.
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
	UID uint32 `json:"uid" desc:"User ID of the file owner."`  // User ID of owner.
	GID uint32 `json:"gid" desc:"Group ID of the file owner."` // Group ID of owner.
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
	Mode       string `json:"mode" desc:"File mode as string (e.g., rwxr-xr-x)."` // File mode as string (e.g., "rwxr-xr-x").
	OwnerRead  bool   `json:"owner_read" desc:"Owner can read."`                  // Owner can read.
	OwnerWrite bool   `json:"owner_write" desc:"Owner can write."`                // Owner can write.
	OwnerExec  bool   `json:"owner_exec" desc:"Owner can execute."`               // Owner can execute.
	GroupRead  bool   `json:"group_read" desc:"Group can read."`                  // Group can read.
	GroupWrite bool   `json:"group_write" desc:"Group can write."`                // Group can write.
	GroupExec  bool   `json:"group_exec" desc:"Group can execute."`               // Group can execute.
	OtherRead  bool   `json:"other_read" desc:"Others can read."`                 // Others can read.
	OtherWrite bool   `json:"other_write" desc:"Others can write."`               // Others can write.
	OtherExec  bool   `json:"other_exec" desc:"Others can execute."`              // Others can execute.
	Setuid     bool   `json:"setuid" desc:"Setuid bit set."`                      // Setuid bit set.
	Setgid     bool   `json:"setgid" desc:"Setgid bit set."`                      // Setgid bit set.
	Sticky     bool   `json:"sticky" desc:"Sticky bit set."`                      // Sticky bit set.
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
	Size     int64     `json:"size,omitempty" desc:"File size in bytes."`      // File size in bytes.
	Access   time.Time `json:"access,omitzero" desc:"Last access time."`       // Last access time.
	Change   time.Time `json:"change,omitzero" desc:"Last modification time."` // Last modification time.
	Creation time.Time `json:"creation,omitzero" desc:"Creation time."`        // Creation time.
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

func (f *FileMetadata) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*f = FileMetadata{}
		return nil
	}

	type fileMetadataAlias FileMetadata

	var decoded struct {
		fileMetadataAlias
		Access   legacyTime `json:"access"`
		Change   legacyTime `json:"change"`
		Creation legacyTime `json:"creation"`
	}

	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*f = FileMetadata(decoded.fileMetadataAlias)
	f.Access = decoded.Access.Time
	f.Change = decoded.Change.Time
	f.Creation = decoded.Creation.Time

	return nil
}

// File Actions.

type FileActions struct {
	Actions  []string `json:"actions,omitempty" desc:"List of actions performed on the file."` // List of actions performed on the file.
	Open     bool     `json:"open,omitempty" desc:"File was opened."`                          // File was opened.
	Read     bool     `json:"read,omitempty" desc:"File was read."`                            // File was read.
	Write    bool     `json:"write,omitempty" desc:"File was written."`                        // File was written.
	Exec     bool     `json:"exec,omitempty" desc:"File was executed (execve)."`               // File was executed (execve).
	Create   bool     `json:"create,omitempty" desc:"File was created."`                       // File was created.
	Unlink   bool     `json:"unlink,omitempty" desc:"File was deleted (unlinked)."`            // File was deleted (unlinked).
	Rename   bool     `json:"rename,omitempty" desc:"File was renamed."`                       // File was renamed.
	Link     bool     `json:"link,omitempty" desc:"File was hardlinked."`                      // File was hardlinked.
	Truncate bool     `json:"truncate,omitempty" desc:"File was truncated."`                   // File was truncated.
	Fsync    bool     `json:"fsync,omitempty" desc:"File was fsynced."`                        // File was fsynced.
	Flock    bool     `json:"flock,omitempty" desc:"File was flocked."`                        // File was flocked.
	Mmap     bool     `json:"mmap,omitempty" desc:"File was mmapped."`                         // File was mmapped.
	Close    bool     `json:"close,omitempty" desc:"File was closed."`                         // File was closed.
	Async    bool     `json:"async,omitempty" desc:"Async I/O performed."`                     // Async I/O performed.
	Seek     bool     `json:"seek,omitempty" desc:"File was seeked."`                          // File was llseeked.
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
	Root FSDir `json:"root,omitzero" desc:"Root directory of the file tree."` // Root directory of the file tree.
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
	Path    string   `json:"path,omitempty" desc:"Absolute path of the directory."` // Absolute path of the directory.
	Base    string   `json:"base,omitempty" desc:"Base name of the directory."`     // Base name of the directory.
	Dirs    []FSDir  `json:"dirs,omitempty" desc:"Subdirectories."`                 // Subdirectories.
	Files   []FSFile `json:"files,omitempty" desc:"Files in this directory."`       // Files in this directory.
	DirHash uint32   `json:"dir_hash,omitempty" desc:"The hash of the directory."`  // The hash of the directory.
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
	Path     string       `json:"path" desc:"Absolute path of the file."`              // Absolute path of the file.
	Base     string       `json:"base" desc:"Base name of the file."`                  // Base name of the file.
	Actions  []string     `json:"actions,omitempty" desc:"Actions taken on the file."` // Actions taken on the file.
	Mode     string       `json:"mode" desc:"File mode."`                              // File mode.
	Owner    FileOwner    `json:"owner" desc:"File owner."`                            // File owner.
	Metadata FileMetadata `json:"metadata,omitzero" desc:"File metadata."`             // File metadata.
	FileHash uint32       `json:"file_hash" desc:"The hash of the file."`              // The hash of the file.
	DirHash  uint32       `json:"dir_hash" desc:"The hash of the directory."`          // The hash of the directory.
	BaseHash uint32       `json:"base_hash" desc:"The hash of the base name."`         // The hash of the base name.
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
	UUID        string `json:"uuid" desc:"UUID of the flow."`                         // UUID of the flow.
	IPVersion   int    `json:"ip_version" desc:"IP version (4 or 6)."`                // IP version.
	Proto       string `json:"proto" desc:"Network protocol."`                        // Protocol.
	ICMP        ICMP   `json:"icmp,omitzero" desc:"ICMP type and code."`              // ICMP.
	Local       Node   `json:"local,omitzero" desc:"Local network endpoint."`         // Local node.
	Remote      Node   `json:"remote,omitzero" desc:"Remote network endpoint."`       // Remote node.
	ServicePort int    `json:"service_port,omitempty" desc:"Service port."`           // Service port.
	Flags       Flags  `json:"flags,omitzero" desc:"Flow state and direction flags."` // Flags.
	Phase       Phase  `json:"phase,omitzero" desc:"Flow lifecycle phase."`           // Flow phase.
	// Hashes for external indexing amongst other ongoing events.
	FlowHash uint32 `json:"flow_hash,omitempty" desc:"The hash of the flow."` // The hash of the flow.
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
	Type string `json:"type" desc:"ICMP type."` // ICMP type.
	Code string `json:"code" desc:"ICMP code."` // ICMP code.
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
	Address string   `json:"address" desc:"IP address."`                 // IP address.
	Name    string   `json:"name" desc:"Primary DNS name."`              // DNS name.
	Names   []string `json:"names,omitempty" desc:"Resolved DNS names."` // DNS names.
	Port    int      `json:"port" desc:"Network port."`                  // Port.
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
	Ingress    bool `json:"ingress" desc:"An ingress packet has been received."`          // An ingress packet has been received.
	Egress     bool `json:"egress" desc:"An egress packet has been sent."`                // An egress packet has been sent.
	Incoming   bool `json:"incoming" desc:"Connection is incoming."`                      // Connection is incoming.
	Outgoing   bool `json:"outgoing" desc:"Connection is outgoing."`                      // Connection is outgoing.
	Started    bool `json:"started" desc:"Connection has been started."`                  // Connection has been started.
	Ongoing    bool `json:"ongoing" desc:"Connection is ongoing."`                        // Connection is ongoing.
	Ended      bool `json:"ended" desc:"Connection has been ended."`                      // Connection has been ended.
	Terminator bool `json:"terminator" desc:"Local node has terminated the connection."`  // Local node has terminated the connection.
	Terminated bool `json:"terminated" desc:"Remote node has terminated the connection."` // Remote node has terminated the connection.
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
	Direction  string `json:"direction" desc:"Direction of the flow."`     // Direction of the flow.
	InitatedBy string `json:"initiated_by" desc:"Who initiated the flow."` // Who initiated the flow.
	Status     string `json:"status" desc:"Status of the flow."`           // Status of the flow.
	EndedBy    string `json:"ended_by" desc:"Who ended the flow."`         // Who ended the flow.
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
	LocalAddr  string `json:"local_addr" desc:"Local IP address."`
	RemoteAddr string `json:"remote_addr" desc:"Remote IP address."`
}

// Flow Aggregate.

type FlowAggregate struct {
	IPVersion int                 `json:"ip_version,omitempty" desc:"IP version (4 or 6)."`             // IP version.
	Protocols []ProtocolAggregate `json:"protocols,omitempty" desc:"List of protocol flow aggregates."` // List of protocol aggregates.
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
	Proto string                   `json:"proto,omitempty" desc:"Network protocol (e.g., TCP, UDP, ICMP)."`                      // Protocol (e.g., TCP, UDP, ICMP).
	Pairs []ProtocolLocalRemoteAgg `json:"pairs,omitempty" desc:"List of unique local and remote node pairs for this protocol."` // List of unique local/remote node pairs for this protocol.
	ICMPs []ICMP                   `json:"icmps,omitempty" desc:"ICMP types and codes when protocol is ICMP."`                   // ICMP types/codes if protocol is ICMP.
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
	Nodes      LocalRemotePair `json:"nodes,omitzero" desc:"Local and remote nodes."`                           // Local and remote nodes.
	PortMatrix []PortCommAgg   `json:"port_matrix,omitempty" desc:"All ports used in flows between the nodes."` // All ports used in flows between the nodes.
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
	Address string   `json:"address" desc:"IP address."`                 // IP address.
	Name    string   `json:"name,omitempty" desc:"Primary DNS name."`    // DNS name.
	Names   []string `json:"names,omitempty" desc:"Resolved DNS names."` // DNS names.
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
	Local  ProtocolNode `json:"local,omitzero" desc:"Local node."`   // Local node.
	Remote ProtocolNode `json:"remote,omitzero" desc:"Remote node."` // Remote node.
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
	SrcPort int   `json:"src_port" desc:"Source port."`      // Source port.
	DstPort int   `json:"dst_port" desc:"Destination port."` // Destination port.
	Phase   Phase `json:"phase,omitzero" desc:"Flow phase."` // Flow phase.
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
	MntNamespaceIDs    []ContainerID `json:"mnt_namespace_ids,omitempty" desc:"Mount namespace IDs."`     // Mount namespace IDs.
	PidNamespaceIDs    []ContainerID `json:"pid_namespace_ids,omitempty" desc:"PID namespace IDs."`       // PID namespace IDs.
	UtsNamespaceIDs    []ContainerID `json:"uts_namespace_ids,omitempty" desc:"UTS namespace IDs."`       // UTS namespace IDs.
	IpcNamespaceIDs    []ContainerID `json:"ipc_namespace_ids,omitempty" desc:"IPC namespace IDs."`       // IPC namespace IDs.
	NetNamespaceIDs    []ContainerID `json:"net_namespace_ids,omitempty" desc:"Network namespace IDs."`   // Net namespace IDs.
	CgroupNamespaceIDs []ContainerID `json:"cgroup_namespace_ids,omitempty" desc:"Cgroup namespace IDs."` // Cgroup namespace IDs.
	Containers         []Container   `json:"containers,omitempty" desc:"Containers."`                     // Containers.
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
	Name string `json:"name,omitempty" desc:"Container name."` // Container name.
	ID   string `json:"id" desc:"Container ID."`               // Container ID.
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
	Source      string `json:"source" desc:"Mount source path."`
	Destination string `json:"destination" desc:"Mount destination path inside the container."`
	Type        string `json:"type" desc:"Mount type."`
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
	ID           string     `json:"id" desc:"Container ID."`                                                     // Container ID.
	Name         string     `json:"name,omitempty" desc:"Container name."`                                       // Container name.
	HostName     string     `json:"hostname,omitempty" desc:"Container hostname."`                               // Host name.
	ImageID      string     `json:"image_id,omitempty" desc:"Container image ID."`                               // Image ID.
	Image        string     `json:"image,omitempty" desc:"Container image name."`                                // Image name.
	Version      string     `json:"version,omitempty" desc:"Container image version."`                           // Image version.
	Runtime      string     `json:"runtime,omitempty" desc:"Container runtime (docker, containerd, etc)."`       // Container runtime ("docker", "containerd", etc).
	Driver       string     `json:"driver,omitempty" desc:"Container storage driver (overlay2, aufs, etc)."`     // Container driver ("overlay2", "aufs", etc).
	PID          int        `json:"pid,omitempty" desc:"Container init process ID."`                             // Process ID.
	ExitCode     int        `json:"exit_code,omitempty" desc:"Container exit code."`                             // Exit code.
	Status       string     `json:"status,omitempty" desc:"Current container status."`                           // Current status.
	IsAttached   bool       `json:"is_attached,omitempty" desc:"Whether the container is attached to the host."` // Whether the container is attached to the host.
	Path         string     `json:"path,omitempty" desc:"Path to the container executable."`                     // Path to the container executable.
	Cwd          string     `json:"cwd,omitempty" desc:"Current working directory of the container."`            // Current working directory.
	CreatedAt    time.Time  `json:"created_at,omitzero" desc:"Container creation time."`                         // Creation time.
	StartedAt    time.Time  `json:"started_at,omitzero" desc:"Container start time."`                            // Start time.
	FinishedAt   time.Time  `json:"finished_at,omitzero" desc:"Container finish time."`                          // Finish time.
	Mounts       []Mount    `json:"mounts,omitempty" desc:"Container filesystem mounts."`                        // Mounts.
	NetworkMode  string     `json:"network_mode,omitempty" desc:"Container network mode."`                       // Network mode.
	CgroupnsMode string     `json:"cgroupns_mode,omitempty" desc:"Container cgroup namespace mode."`             // Cgroup namespace mode.
	IpcMode      string     `json:"ipc_mode,omitempty" desc:"Container IPC mode."`                               // IPC mode.
	PidMode      string     `json:"pid_mode,omitempty" desc:"Container PID mode."`                               // PID mode.
	UsernsMode   string     `json:"userns_mode,omitempty" desc:"Container user namespace mode."`                 // User namespace mode.
	UTSMode      string     `json:"uts_mode,omitempty" desc:"Container UTS namespace mode."`                     // UTS namespace mode.
	Env          []string   `json:"env,omitempty" desc:"Container environment variables."`                       // Environment variables.
	Cmd          []string   `json:"cmd,omitempty" desc:"Container command and arguments."`                       // Command.
	Namespaces   Namespaces `json:"namespaces,omitzero" desc:"Container Linux namespaces."`                      // Namespaces.
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

func (c *Container) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*c = Container{}
		return nil
	}

	type containerAlias Container

	var decoded struct {
		containerAlias
		CreatedAt  legacyTime `json:"created_at"`
		StartedAt  legacyTime `json:"started_at"`
		FinishedAt legacyTime `json:"finished_at"`
	}

	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*c = Container(decoded.containerAlias)
	c.CreatedAt = decoded.CreatedAt.Time
	c.StartedAt = decoded.StartedAt.Time
	c.FinishedAt = decoded.FinishedAt.Time

	return nil
}

//
// Profiling event.
//

// ProcessTree.

type ProcessTree struct {
	PID        uint32   `json:"pid,omitempty" desc:"Process ID."` // Process ID.
	Process    string   `json:"process,omitempty" desc:"Process command line."`
	Executable string   `json:"executable,omitempty" desc:"Process executable path."`
	Arguments  string   `json:"arguments,omitempty" desc:"Process command-line arguments."`
	GitHubStep string   `json:"github_step,omitempty" desc:"GitHub Actions workflow step name."`
	Ancestry   []string `json:"ancestry,omitempty" desc:"Process ancestry chain."`
}

func (pt ProcessTree) Clone() ProcessTree {
	return ProcessTree{
		PID:        pt.PID,
		Process:    pt.Process,
		Executable: pt.Executable,
		Arguments:  pt.Arguments,
		GitHubStep: pt.GitHubStep,
		Ancestry:   append([]string(nil), pt.Ancestry...),
	}
}

func (pt ProcessTree) IsZero() bool {
	return pt.PID == 0 &&
		pt.Process == "" &&
		pt.Executable == "" &&
		pt.Arguments == "" &&
		pt.GitHubStep == "" &&
		len(pt.Ancestry) == 0
}

func (pt ProcessTree) MarshalJSON() ([]byte, error) {
	if pt.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		PID        *uint32  `json:"pid,omitempty"`
		Process    string   `json:"process,omitempty"`
		Executable string   `json:"executable,omitempty"`
		Arguments  string   `json:"arguments,omitempty"`
		GitHubStep string   `json:"github_step,omitempty"`
		Ancestry   []string `json:"ancestry,omitempty"`
	}{
		Process:    pt.Process,
		Executable: pt.Executable,
		Arguments:  pt.Arguments,
		GitHubStep: pt.GitHubStep,
		Ancestry:   pt.Ancestry,
	}

	if pt.PID != 0 {
		pid := pt.PID
		created.PID = &pid
	}

	return json.Marshal(created)
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
	Latitude      float64 `json:"latitude,omitempty" desc:"Geographic latitude."`
	Longitude     float64 `json:"longitude,omitempty" desc:"Geographic longitude."`
	Continent     string  `json:"continent,omitempty" desc:"Continent name."`
	ContinentCode string  `json:"continent_code,omitempty" desc:"Two-letter continent code."`
	Country       string  `json:"country,omitempty" desc:"Country name."`
	CountryCode   string  `json:"country_code,omitempty" desc:"Two-letter ISO country code."`
	Region        string  `json:"region,omitempty" desc:"Region or state code."`
	RegionName    string  `json:"region_name,omitempty" desc:"Region or state name."`
	City          string  `json:"city,omitempty" desc:"City name."`
	ISP           string  `json:"isp,omitempty" desc:"Internet service provider name."`
	Org           string  `json:"org,omitempty" desc:"Organization name."`
	Asname        string  `json:"asname,omitempty" desc:"Autonomous system name and number."`
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
	Result        Result        `json:"result" desc:"Evaluation result for the peer (pass, attention, fail)."`
	Detections    []string      `json:"detections,omitempty" desc:"Detection UUIDs associated with the peer."`
	Protocol      string        `json:"protocol" desc:"Network protocol used to communicate with the peer."`
	LocalAddress  string        `json:"local_address" desc:"Local IP or socket address."`
	RemoteAddress string        `json:"remote_address" desc:"Remote IP or socket address."`
	LocalNames    []string      `json:"local_names,omitempty" desc:"Resolved local domain names."`
	RemoteNames   []string      `json:"remote_names,omitempty" desc:"Resolved remote domain names."`
	RemotePorts   []string      `json:"remote_ports,omitempty" desc:"Remote ports contacted on the peer."`
	ProcTrees     []ProcessTree `json:"proc_trees,omitempty" desc:"Process trees that communicated with the peer."`
	RemoteGeoInfo GeoIPLocation `json:"remote_geo_info,omitzero" desc:"Geographic IP location of the remote peer."`
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
	Peers   []Peer   `json:"peers,omitempty" desc:"Network peers observed in this traffic direction."`
	Domains []string `json:"domains,omitempty" desc:"Domain names observed in this traffic direction."`
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
	Egress  Direction `json:"egress,omitzero" desc:"Outbound network traffic profile."`
	Ingress Direction `json:"ingress,omitzero" desc:"Inbound network traffic profile."`
	Local   Direction `json:"local,omitzero" desc:"Local network traffic profile."`
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
	TotalDomains     uint `json:"total_domains" desc:"Total number of domains observed in this direction."`
	TotalConnections uint `json:"total_connections" desc:"Total number of connections observed in this direction."`
}

func (int DirectionNetTelemetry) Clone() DirectionNetTelemetry {
	return DirectionNetTelemetry{
		TotalDomains:     int.TotalDomains,
		TotalConnections: int.TotalConnections,
	}
}

func (int DirectionNetTelemetry) IsZero() bool {
	// Both values must be zero to be considered zero.
	return int.TotalDomains == 0 && int.TotalConnections == 0
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
	Egress  DirectionNetTelemetry `json:"egress,omitzero" desc:"Outbound network telemetry summary."`
	Ingress DirectionNetTelemetry `json:"ingress,omitzero" desc:"Inbound network telemetry summary."`
	Local   DirectionNetTelemetry `json:"local,omitzero" desc:"Local network telemetry summary."`
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
	Network NetTelemetry      `json:"network,omitzero" desc:"Network telemetry summary."`
	Capture *CaptureTelemetry `json:"capture,omitempty" desc:"Optional per-job capture completeness evidence."`
}

func (t Telemetry) Clone() Telemetry {
	return Telemetry{
		Network: t.Network.Clone(),
		Capture: t.Capture.Clone(),
	}
}

func (t Telemetry) IsZero() bool {
	return t.Network.IsZero() && t.Capture == nil
}

func (t Telemetry) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		Network NetTelemetry      `json:"network"`
		Capture *CaptureTelemetry `json:"capture,omitempty"`
	}{
		Network: t.Network,
		Capture: t.Capture,
	})
}

// Evidence: A single piece of evidence that supports an assertion.

type Evidence struct {
	Timestamp time.Time `json:"timestamp" desc:"Event timestamp."`                          // Event timestamp.
	EventName string    `json:"event_name" desc:"Event name."`                              // Event name.
	Peer      Peer      `json:"peer,omitzero" desc:"Network peer supporting the evidence."` // Peer.
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

func (e *Evidence) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*e = Evidence{}
		return nil
	}

	type evidenceAlias Evidence

	var decoded struct {
		evidenceAlias
		Timestamp legacyTime `json:"timestamp"`
	}

	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*e = Evidence(decoded.evidenceAlias)
	e.Timestamp = decoded.Timestamp.Time

	return nil
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

func (rid ResultID) MarshalText() ([]byte, error) {
	return []byte(rid.String()), nil
}

func (rid *ResultID) UnmarshalText(text []byte) error {
	s := string(text)
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

func (rid ResultID) MarshalJSON() ([]byte, error) {
	return json.Marshal(rid.String())
}

func (rid *ResultID) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*rid = ResultIDNone
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		return rid.UnmarshalText([]byte(s))
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

func (r Result) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}

func (r *Result) UnmarshalText(text []byte) error {
	s := string(text)
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
		return r.UnmarshalText([]byte(s))
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
	ClassID     string     `json:"class_id,omitempty" desc:"Class ID of the assertion."`                 // Class ID of assertion.
	AssertionID string     `json:"assertion_id,omitempty" desc:"Assertion identifier."`                  // Assertion ID.
	Result      Result     `json:"result" desc:"Result of the assertion (pass, attention, fail)."`       // Result of the assertion.
	Description string     `json:"description,omitempty" desc:"Description of the assertion."`           // Description of the assertion.
	ResultID    ResultID   `json:"id" desc:"Result identifier."`                                         // Result ID.
	Evidence    []Evidence `json:"evidence,omitempty" desc:"Evidence detections supporting the result."` // Detections supporting the result.
}

func (a Assertion) Clone() Assertion {
	evidence := make([]Evidence, len(a.Evidence))
	for i, e := range a.Evidence {
		evidence[i] = e.Clone()
	}
	return Assertion{
		ClassID:     a.ClassID,
		AssertionID: a.AssertionID,
		Result:      a.Result,
		Description: a.Description,
		ResultID:    a.ResultID,
		Evidence:    evidence,
	}
}

func (a Assertion) IsZero() bool {
	return a.ClassID == "" &&
		a.AssertionID == "" &&
		a.Result.IsZero() &&
		a.Description == "" &&
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

	resultID := a.ResultID.String()

	return json.Marshal(struct {
		ClassID     string     `json:"class_id,omitempty"`
		AssertionID string     `json:"assertion_id,omitempty"`
		Result      string     `json:"result"`
		Description string     `json:"description,omitempty"`
		ResultID    string     `json:"id"`
		Evidence    []Evidence `json:"evidence,omitempty"`
	}{
		ClassID:     a.ClassID,
		AssertionID: a.AssertionID,
		Result:      result,
		Description: a.Description,
		ResultID:    resultID,
		Evidence:    a.Evidence,
	})
}

type DigestedDetection struct {
	AssertionID string        `json:"assertion_id,omitempty" desc:"Assertion ID matching the corresponding assertion."` // Assertion ID that equals the 'assertion_id' field of the Assertion struct.
	Metadata    Metadata      `json:"metadata,omitzero" desc:"Metadata associated with the detection."`                 // Metadata associated with the detection.
	Score       Score         `json:"score,omitzero" desc:"Security risk score associated with the detection."`         // Score associated with the detection.
	Result      Result        `json:"result,omitempty" desc:"Result of the detection (pass, attention, fail)."`         // Result of the detection.
	ProcTrees   []ProcessTree `json:"proc_trees,omitempty" desc:"Process trees associated with the detection."`         // Process trees associated with the detection.
}

func (dd DigestedDetection) Clone() DigestedDetection {
	procTrees := make([]ProcessTree, len(dd.ProcTrees))
	for i, tree := range dd.ProcTrees {
		procTrees[i] = tree.Clone()
	}
	return DigestedDetection{
		AssertionID: dd.AssertionID,
		Result:      dd.Result,
		Metadata:    dd.Metadata.Clone(),
		Score:       dd.Score.Clone(),
		ProcTrees:   procTrees,
	}
}

func (dd DigestedDetection) IsZero() bool {
	return dd.AssertionID == "" &&
		dd.Result.IsZero() &&
		dd.Metadata.IsZero() &&
		dd.Score.IsZero() &&
		len(dd.ProcTrees) == 0
}

func (dd DigestedDetection) MarshalJSON() ([]byte, error) {
	if dd.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		AssertionID string        `json:"assertion_id,omitempty"`
		Result      string        `json:"result,omitempty"`
		Metadata    *Metadata     `json:"metadata,omitempty"`
		Score       *Score        `json:"score,omitempty"`
		ProcTrees   []ProcessTree `json:"proc_trees,omitempty"`
	}{
		AssertionID: dd.AssertionID,
		Result:      dd.Result.String(),
	}

	if !dd.Metadata.IsZero() {
		created.Metadata = &dd.Metadata
	}
	if !dd.Score.IsZero() {
		created.Score = &dd.Score
	}
	if len(dd.ProcTrees) > 0 {
		created.ProcTrees = dd.ProcTrees
	}

	return json.Marshal(created)
}

func (dd *DigestedDetection) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*dd = DigestedDetection{}
		return nil
	}

	type digestedDetectionAlias DigestedDetection

	var decoded digestedDetectionAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*dd = DigestedDetection(decoded)

	return nil
}

type ProfileDetection struct {
	ClassID            string              `json:"class_id,omitempty" desc:"The class ID of the detection, corresponding to the assertion class ID."` // The class ID of the detection, which corresponds to the class ID of an assertion.
	DigestedDetections []DigestedDetection `json:"digested_detections,omitempty" desc:"The digested detections that belong to this class."`           // The digested detections that are part of this class.
}

func (d ProfileDetection) Clone() ProfileDetection {
	detections := make([]DigestedDetection, len(d.DigestedDetections))
	for i, dd := range d.DigestedDetections {
		detections[i] = dd.Clone()
	}
	return ProfileDetection{
		ClassID:            d.ClassID,
		DigestedDetections: detections,
	}
}

func (d ProfileDetection) IsZero() bool {
	return d.ClassID == "" &&
		len(d.DigestedDetections) == 0
}

func (d ProfileDetection) MarshalJSON() ([]byte, error) {
	if d.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		ClassID            string              `json:"class_id,omitempty"`
		DigestedDetections []DigestedDetection `json:"digested_detections,omitempty"`
	}{
		ClassID: d.ClassID,
	}

	if len(d.DigestedDetections) > 0 {
		created.DigestedDetections = d.DigestedDetections
	}

	return json.Marshal(created)
}

func (d *ProfileDetection) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*d = ProfileDetection{}
		return nil
	}

	type profileDetectionAlias ProfileDetection

	var decoded profileDetectionAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*d = ProfileDetection(decoded)

	return nil
}

// Behavior Profile Event.

type Profile struct {
	Base
	Network           NetProfile         `json:"network,omitzero" desc:"Network traffic behavior profile."`
	ProfileDetections []ProfileDetection `json:"profile_detections,omitempty" desc:"Detections grouped by assertion class."`
	Telemetry         Telemetry          `json:"telemetry,omitzero" desc:"Aggregated telemetry summary for the profile."`
	Assertions        []Assertion        `json:"assertions,omitempty" desc:"Security policy assertions evaluated for the profile."`
}

func (p Profile) Clone() Profile {
	assertions := make([]Assertion, len(p.Assertions))
	for i, a := range p.Assertions {
		assertions[i] = a.Clone()
	}

	detections := make([]ProfileDetection, len(p.ProfileDetections))
	for i, d := range p.ProfileDetections {
		detections[i] = d.Clone()
	}

	return Profile{
		Base:              p.Base.Clone(),
		Network:           p.Network.Clone(),
		Telemetry:         p.Telemetry.Clone(),
		Assertions:        assertions,
		ProfileDetections: detections,
	}
}

func (p Profile) IsZero() bool {
	return p.Base.IsZero() &&
		p.Network.IsZero() &&
		p.Telemetry.IsZero() &&
		len(p.Assertions) == 0 &&
		len(p.ProfileDetections) == 0
}

func (p Profile) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		UUID              *string            `json:"uuid,omitempty"`
		Timestamp         *time.Time         `json:"timestamp,omitempty"`
		Note              *string            `json:"note,omitempty"`
		Metadata          *Metadata          `json:"metadata,omitempty"`
		Attenuator        *Attenuator        `json:"attenuator,omitempty"`
		Score             *Score             `json:"score,omitempty"`
		Background        *Background        `json:"background,omitempty"`
		Scenarios         *Scenarios         `json:"scenarios,omitempty"`
		Network           *NetProfile        `json:"network,omitempty"`
		Telemetry         *Telemetry         `json:"telemetry,omitempty"`
		Assertions        []Assertion        `json:"assertions,omitempty"`
		ProfileDetections []ProfileDetection `json:"profile_detections,omitempty"`
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
	if len(p.ProfileDetections) > 0 {
		created.ProfileDetections = p.ProfileDetections
	}

	return json.Marshal(created)
}

func (p *Profile) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*p = Profile{}
		return nil
	}

	var decoded struct {
		baseAlias
		Timestamp         legacyTime         `json:"timestamp"`
		Network           NetProfile         `json:"network"`
		ProfileDetections []ProfileDetection `json:"profile_detections"`
		Telemetry         Telemetry          `json:"telemetry"`
		Assertions        []Assertion        `json:"assertions"`
	}

	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*p = Profile{
		Base:              Base(decoded.baseAlias),
		Network:           decoded.Network,
		Telemetry:         decoded.Telemetry,
		Assertions:        decoded.Assertions,
		ProfileDetections: decoded.ProfileDetections,
	}
	p.Timestamp = decoded.Timestamp.Time

	return nil
}
