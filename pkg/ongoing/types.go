package ongoing

import (
	"encoding/json"
)

// All detection events have these fields.

type Base struct {
	UUID       string     `json:"uuid"`       // The unique ID of the detection.
	Timestamp  string     `json:"timestamp"`  // The timestamp of the detection.
	Note       string     `json:"note"`       // A note about the detection.
	Metadata   Metadata   `json:"metadata"`   // The detection metadata.
	Attenuator Attenuator `json:"attenuator"` // The attenuator of the detection.
	Score      Score      `json:"score"`      // Detection Security Risk Score.
	Background Background `json:"background"` // The detection context.
	Scenario   Scenario   `json:"scenario"`   // GitHub, Kubernetes, Host, etc.
}

func (b Base) Clone() Base {
	return Base{
		UUID:       b.UUID,
		Timestamp:  b.Timestamp,
		Note:       b.Note,
		Metadata:   b.Metadata.Clone(),
		Attenuator: b.Attenuator.Clone(),
		Score:      b.Score.Clone(),
		Background: b.Background.Clone(),
		Scenario:   b.Scenario.Clone(),
	}
}

func (b Base) IsZero() bool {
	return b.UUID == "" &&
		b.Timestamp == "" &&
		b.Note == "" &&
		b.Metadata.IsZero() &&
		b.Attenuator.IsZero() &&
		b.Score.IsZero() &&
		b.Background.IsZero() &&
		b.Scenario.IsZero()
}

func (b Base) MarshalJSON() ([]byte, error) {
	if b.IsZero() {
		return []byte("null"), nil
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
	if !b.Scenario.IsZero() {
		result["scenario"] = b.Scenario
	}

	return json.Marshal(result)
}

func unmarshalJSONToMap(data []byte) (map[string]any, error) {
	var m map[string]any
	if len(data) == 0 || string(data) == "null" {
		return nil, nil
	}
	err := json.Unmarshal(data, &m)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (b Base) MarshalJSONMap() (map[string]any, error) {
	if b.IsZero() {
		return nil, nil
	}

	bBytes, err := b.MarshalJSON()
	if err != nil {
		return nil, err
	}

	m, err := unmarshalJSONToMap(bBytes)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (b Base) SetScore(score Score) {
	b.Score = score
}

func (b Base) GetScore() Score {
	return b.Score
}

func (b Base) SetAttenuator(attenuator Attenuator) {
	b.Attenuator = attenuator
}

func (b Base) GetAttenuator() Attenuator {
	return b.Attenuator
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

	result := make(map[string]any)

	// Always included fields.
	result["kind"] = m.Kind
	result["name"] = m.Name
	result["format"] = m.Format
	result["version"] = m.Version

	// Omit empty fields.
	if m.Description != "" {
		result["description"] = m.Description
	}
	if m.Tactic != "" {
		result["tactic"] = m.Tactic
	}
	if m.Technique != "" {
		result["technique"] = m.Technique
	}
	if m.SubTechnique != "" {
		result["subtechnique"] = m.SubTechnique
	}
	if m.Importance != "" {
		result["importance"] = m.Importance
	}
	if m.Documentation != "" {
		result["documentation"] = m.Documentation
	}

	return json.Marshal(result)
}

// Security Risk Score.

type Score struct {
	Source        string  `json:"source"`         // Source of the score.
	Severity      int     `json:"severity"`       // Severity number of the detection (0-100).
	SeverityLevel string  `json:"severity_level"` // Severity level of the detection (none, low, medium, high, critical).
	Confidence    float64 `json:"confidence"`     // Confidence percentage of the detection (0.0-1.0).
	RiskScore     float64 `json:"risk_score"`     // Calculated and rounded up risk score of the detection (0.0-100.0).
	Reason        string  `json:"reason"`         // Detailed Reason of why this score.
}

func (s Score) Clone() Score {
	return Score{
		Source:        s.Source,
		Severity:      s.Severity,
		SeverityLevel: s.SeverityLevel,
		Confidence:    s.Confidence,
		RiskScore:     s.RiskScore,
		Reason:        s.Reason,
	}
}

// IsZero checks if Score is empty.
// Returns true if all fields have zero values.
func (s Score) IsZero() bool {
	return s.Source == "" &&
		s.Severity == 0 &&
		s.SeverityLevel == "" &&
		s.Confidence == 0 &&
		s.RiskScore == 0 &&
		s.Reason == ""
}

// MarshalJSON implements json.Marshaler.
//
// MarshalJSON ensures that an empty Score is serialized
// as null. All valid severity levels including "none" are
// properly serialized to their corresponding string values.
// SeverityLevel should not be empty.
//
// RiskScore must be calculated if severity_level != "none".
// When RiskScore is zero, it is omitted from JSON. This includes
// the case where severity_level == "none", meaning no security impact.
//
// Always check severity and severity_level before risk_score.
func (s Score) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Always included fields.
	result["source"] = s.Source
	result["severity"] = s.Severity
	result["severity_level"] = s.SeverityLevel
	result["confidence"] = s.Confidence

	// RiskScore must be calculated if severity_level != "none".
	// if severity_level == "none" then it probably means no
	// security impact, so no risk. In this case risk_score is not
	// serialized.
	if s.RiskScore != 0 {
		result["risk_score"] = s.RiskScore
	}

	if s.Reason != "" {
		result["reason"] = s.Reason
	}

	return json.Marshal(result)
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

	result := make(map[string]any)

	// Always included fields.
	result["attenuated_by"] = a.AttenuatedBy
	result["interpretation"] = a.Interpretation
	result["is_false_positive"] = a.IsFalsePositive
	result["new_severity"] = a.NewSeverity
	result["new_severity_level"] = a.NewSeverityLevel
	result["new_confidence"] = a.NewConfidence
	result["new_risk_score"] = a.NewRiskScore

	// Omit empty fields.
	if a.Thinking != "" {
		result["thinking"] = a.Thinking
	}

	return json.Marshal(result)
}

// Context.

type Background struct {
	Files      FileAggregate      `json:"files"`
	Flows      FlowAggregate      `json:"flows"`
	Containers ContainerAggregate `json:"containers"`
	Ancestry   []Process          `json:"ancestry"`
}

func (b Background) Clone() Background {
	ancestry := make([]Process, len(b.Ancestry))
	copy(ancestry, b.Ancestry)
	return Background{
		Files:      b.Files.Clone(),
		Flows:      b.Flows.Clone(),
		Containers: b.Containers.Clone(),
		Ancestry:   ancestry,
	}
}

func (b Background) IsZero() bool {
	return b.Files.IsZero() &&
		b.Flows.IsZero() &&
		b.Containers.IsZero() &&
		len(b.Ancestry) == 0
}

func (b Background) MarshalJSON() ([]byte, error) {
	if b.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Omit empty fields.
	if !b.Files.IsZero() {
		result["files"] = b.Files
	}
	if !b.Flows.IsZero() {
		result["flows"] = b.Flows
	}
	if !b.Containers.IsZero() {
		result["containers"] = b.Containers
	}
	if len(b.Ancestry) > 0 {
		result["ancestry"] = b.Ancestry
	}

	return json.Marshal(result)
}

// File Access Detection Event.

type FileAccess struct {
	Base
	File File `json:"file"`
}

func (f FileAccess) Clone() FileAccess {
	return FileAccess{
		Base: f.Base.Clone(),
		File: f.File.Clone(),
	}
}

func (f FileAccess) IsZero() bool {
	return f.Base.IsZero() && f.File.IsZero()
}

func (f FileAccess) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	if !f.Base.IsZero() {
		baseMap, err := f.Base.MarshalJSONMap()
		if err != nil {
			return nil, err
		}
		for k, v := range baseMap {
			result[k] = v
		}
	}

	// Omit empty fields.
	if !f.File.IsZero() {
		result["file"] = f.File
	}

	return json.Marshal(result)
}

// Execution Detection Event.

type Execution struct {
	Base
	Process Process `json:"process"`
}

func (e Execution) Clone() Execution {
	return Execution{
		Base:    e.Base.Clone(),
		Process: e.Process.Clone(),
	}
}

func (e Execution) IsZero() bool {
	return e.Base.IsZero() && e.Process.IsZero()
}

func (e Execution) MarshalJSON() ([]byte, error) {
	if e.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	if !e.Base.IsZero() {
		baseMap, err := e.Base.MarshalJSONMap()
		if err != nil {
			return nil, err
		}
		for k, v := range baseMap {
			result[k] = v
		}
	}

	// Omit empty fields.
	if !e.Process.IsZero() {
		result["process"] = e.Process
	}

	return json.Marshal(result)
}

// Network Peers Detection Event.

type NetworkPeer struct {
	Base
	Flow Flow `json:"flow"`
}

func (n NetworkPeer) Clone() NetworkPeer {
	return NetworkPeer{
		Base: n.Base.Clone(),
		Flow: n.Flow.Clone(),
	}
}

func (n NetworkPeer) IsZero() bool {
	return n.Base.IsZero() && n.Flow.IsZero()
}

func (n NetworkPeer) MarshalJSON() ([]byte, error) {
	if n.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	if !n.Base.IsZero() {
		baseMap, err := n.Base.MarshalJSONMap()
		if err != nil {
			return nil, err
		}
		for k, v := range baseMap {
			result[k] = v
		}
	}

	// Omit empty fields.
	if !n.Flow.IsZero() {
		result["flow"] = n.Flow
	}

	return json.Marshal(result)
}

// Network Flow Event.

type NetworkFlow struct {
	Base
	Flow Flow `json:"flow"`
}

func (n NetworkFlow) Clone() NetworkFlow {
	return NetworkFlow{
		Base: n.Base.Clone(),
		Flow: n.Flow.Clone(),
	}
}

func (n NetworkFlow) IsZero() bool {
	return n.Base.IsZero() && n.Flow.IsZero()
}

func (n NetworkFlow) MarshalJSON() ([]byte, error) {
	if n.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	if !n.Base.IsZero() {
		baseMap, err := n.Base.MarshalJSONMap()
		if err != nil {
			return nil, err
		}
		for k, v := range baseMap {
			result[k] = v
		}
	}

	// Omit empty fields.
	if !n.Flow.IsZero() {
		result["flow"] = n.Flow
	}

	return json.Marshal(result)
}

// Drop IP Detection Event.

type DropIP struct {
	Base
	IP    string   `json:"ip"`    // The IP that was dropped.
	Names []string `json:"names"` // The names of the IP.
	Flow  Flow     `json:"flow"`  // The flow that triggered the drop.
}

func (d DropIP) Clone() DropIP {
	names := make([]string, len(d.Names))
	copy(names, d.Names)
	return DropIP{
		Base:  d.Base.Clone(),
		IP:    d.IP,
		Names: names,
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

	result := make(map[string]any)

	if !d.Base.IsZero() {
		baseMap, err := d.Base.MarshalJSONMap()
		if err != nil {
			return nil, err
		}
		for k, v := range baseMap {
			result[k] = v
		}
	}

	// Omit empty fields.
	if d.IP != "" {
		result["ip"] = d.IP
	}
	if len(d.Names) > 0 {
		result["names"] = d.Names
	}
	if !d.Flow.IsZero() {
		result["flow"] = d.Flow
	}

	return json.Marshal(result)
}

// Process.

type Process struct {
	Start      string     `json:"start"`       // The start time of the process.
	Exit       string     `json:"exit"`        // The exit time of the process.
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
}

func (p Process) Clone() Process {
	return p
}

func (p Process) IsZero() bool {
	return p.Start == "" &&
		p.Exit == "" &&
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
		p.Namespaces.IsZero()
}

func (p Process) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Always included fields.
	result["start"] = p.Start
	result["exit"] = p.Exit
	result["retcode"] = p.Code
	result["uid"] = p.UID
	result["pid"] = p.Pid
	result["ppid"] = p.Ppid
	result["comm"] = p.Comm
	result["cmd"] = p.Cmd
	result["exe"] = p.Exe

	// Omit empty fields.
	if p.Args != "" {
		result["args"] = p.Args
	}
	if p.Envs != "" {
		result["envs"] = p.Envs
	}
	if p.Loader != "" {
		result["loader"] = p.Loader
	}
	if p.PrevExe != "" {
		result["prev_exe"] = p.PrevExe
	}
	if p.PrevArgs != "" {
		result["prev_args"] = p.PrevArgs
	}
	if p.PrevEnvs != "" {
		result["prev_envs"] = p.PrevEnvs
	}
	if p.PrevLoader != "" {
		result["prev_loader"] = p.PrevLoader
	}
	if !p.Namespaces.IsZero() {
		result["namespaces"] = p.Namespaces
	}

	return json.Marshal(result)
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

	result := make(map[string]any)

	// Omit empty fields.
	if n.MNTNs != 0 {
		result["mnt_ns"] = n.MNTNs
	}
	if n.PIDNs != 0 {
		result["pid_ns"] = n.PIDNs
	}
	if n.UTSNs != 0 {
		result["uts_ns"] = n.UTSNs
	}
	if n.IPCNs != 0 {
		result["ipc_ns"] = n.IPCNs
	}
	if n.NetNs != 0 {
		result["net_ns"] = n.NetNs
	}
	if n.CgroupNs != 0 {
		result["cgroup_ns"] = n.CgroupNs
	}

	return json.Marshal(result)
}

// File.

type File struct {
	// Basic file identity.
	Path        string          `json:"path"`        // Absolute path to the file.
	Dir         string          `json:"dir"`         // Directory containing the file.
	Base        string          `json:"basename"`    // Base name of the file.
	Type        string          `json:"type"`        // File type: regular, directory, symlink, socket, block, char, fifo.
	Owner       FileOwner       `json:"owner"`       // File owner.
	Actions     FileActions     `json:"actions"`     // Detailed actions performed on the file.
	Permissions FilePermissions `json:"permissions"` // File permissions.
	SpecialBits FileSpecialBits `json:"special"`     // Special permission bits.
	Metadata    FileMetadata    `json:"metadata"`    // File metadata.
}

func (f File) Clone() File {
	return File{
		Path:        f.Path,
		Dir:         f.Dir,
		Base:        f.Base,
		Type:        f.Type,
		Owner:       f.Owner,
		Actions:     f.Actions.Clone(),
		Permissions: f.Permissions,
		SpecialBits: f.SpecialBits,
		Metadata:    f.Metadata,
	}
}

func (f File) IsZero() bool {
	return f.Path == "" &&
		f.Dir == "" &&
		f.Base == "" &&
		f.Type == "" &&
		f.Owner.IsZero() &&
		f.Actions.IsZero() &&
		f.Permissions.IsZero() &&
		f.SpecialBits.IsZero() &&
		f.Metadata.IsZero()
}

func (f File) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Always included fields.
	result["path"] = f.Path
	result["dir"] = f.Dir
	result["basename"] = f.Base
	result["type"] = f.Type
	result["owner"] = f.Owner
	result["special"] = f.SpecialBits

	// Omit empty fields.
	if !f.Actions.IsZero() {
		result["actions"] = f.Actions
	}
	if !f.Permissions.IsZero() {
		result["permissions"] = f.Permissions
	}
	if !f.Metadata.IsZero() {
		result["metadata"] = f.Metadata
	}

	return json.Marshal(result)
}

type FileOwner struct {
	UID uint32 `json:"uid"` // User ID of owner.
	GID uint32 `json:"gid"` // Group ID of owner.
}

func (f FileOwner) IsZero() bool {
	// Note: root user and group have zero values for UID and GID.
	return f.UID == 0 && f.GID == 0
}

func (f FileOwner) MarshalJSON() ([]byte, error) {
	result := make(map[string]any)

	// Always included fields.
	result["uid"] = f.UID
	result["gid"] = f.GID

	return json.Marshal(result)
}

type FileSpecialBits struct {
	Setuid bool `json:"setuid"` // Setuid bit set.
	Setgid bool `json:"setgid"` // Setgid bit set.
	Sticky bool `json:"sticky"` // Sticky bit set.
}

func (f FileSpecialBits) IsZero() bool {
	// Note: this is possible to be true and not zero.
	return !f.Setuid && !f.Setgid && !f.Sticky
}

func (f FileSpecialBits) MarshalJSON() ([]byte, error) {
	result := make(map[string]any)

	// Omit empty fields.
	if f.Setuid {
		result["setuid"] = f.Setuid
	}
	if f.Setgid {
		result["setgid"] = f.Setgid
	}
	if f.Sticky {
		result["sticky"] = f.Sticky
	}

	return json.Marshal(result)
}

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

	result := make(map[string]any)

	// Always included fields.
	result["mode"] = f.Mode
	result["owner_read"] = f.OwnerRead
	result["owner_write"] = f.OwnerWrite
	result["owner_exec"] = f.OwnerExec
	result["group_read"] = f.GroupRead
	result["group_write"] = f.GroupWrite
	result["group_exec"] = f.GroupExec
	result["other_read"] = f.OtherRead
	result["other_write"] = f.OtherWrite
	result["other_exec"] = f.OtherExec

	return json.Marshal(result)
}

type FileMetadata struct {
	Size     int64  `json:"size"`     // File size in bytes.
	Access   string `json:"access"`   // Last access time.
	Change   string `json:"change"`   // Last modification time.
	Creation string `json:"creation"` // Creation time.
}

func (f FileMetadata) IsZero() bool {
	return f.Size == 0 &&
		f.Access == "" &&
		f.Change == "" &&
		f.Creation == ""
}

func (f FileMetadata) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Omit empty fields.
	if f.Size != 0 {
		result["size"] = f.Size
	}
	if f.Access != "" {
		result["access"] = f.Access
	}
	if f.Change != "" {
		result["change"] = f.Change
	}
	if f.Creation != "" {
		result["creation"] = f.Creation
	}

	return json.Marshal(result)
}

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
	actions := make([]string, len(f.Actions))
	copy(actions, f.Actions)
	return FileActions{
		Actions:  actions,
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

	result := make(map[string]any)

	result["actions"] = f.Actions
	result["open"] = f.Open
	result["read"] = f.Read
	result["write"] = f.Write
	result["exec"] = f.Exec
	result["create"] = f.Create
	result["unlink"] = f.Unlink
	result["rename"] = f.Rename
	result["link"] = f.Link
	result["truncate"] = f.Truncate
	result["fsync"] = f.Fsync
	result["flock"] = f.Flock
	result["mmap"] = f.Mmap
	result["close"] = f.Close
	result["async"] = f.Async
	result["seek"] = f.Seek

	return json.Marshal(result)
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
	return json.Marshal(f.Root)
}

// FSDir.

type FSDir struct {
	Path  string   `json:"path"`  // Absolute path of the directory.
	Base  string   `json:"base"`  // Base name of the directory.
	Dirs  []FSDir  `json:"dirs"`  // Subdirectories.
	Files []FSFile `json:"files"` // Files in this directory.
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
		Path:  f.Path,
		Base:  f.Base,
		Dirs:  dirs,
		Files: files,
	}
}

func (f FSDir) IsZero() bool {
	return f.Path == "" &&
		f.Base == "" &&
		len(f.Dirs) == 0 &&
		len(f.Files) == 0
}

func (f FSDir) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Omit empty fields.
	if f.Path != "" {
		result["path"] = f.Path
	}
	if f.Base != "" {
		result["base"] = f.Base
	}
	if len(f.Dirs) > 0 {
		result["dirs"] = f.Dirs
	}
	if len(f.Files) > 0 {
		result["files"] = f.Files
	}

	return json.Marshal(result)
}

type FSFile struct {
	Path     string       `json:"path"`     // Absolute path of the file.
	Base     string       `json:"base"`     // Base name of the file.
	Actions  []string     `json:"actions"`  // Actions taken on the file.
	Mode     string       `json:"mode"`     // File mode.
	Owner    FileOwner    `json:"owner"`    // File owner.
	Metadata FileMetadata `json:"metadata"` // File metadata.
}

func (f FSFile) Clone() FSFile {
	actions := make([]string, len(f.Actions))
	copy(actions, f.Actions)
	return FSFile{
		Path:     f.Path,
		Base:     f.Base,
		Actions:  actions,
		Mode:     f.Mode,
		Owner:    f.Owner,
		Metadata: f.Metadata,
	}
}

func (f FSFile) IsZero() bool {
	return f.Path == "" &&
		f.Base == "" &&
		len(f.Actions) == 0 &&
		f.Mode == "" &&
		f.Owner.IsZero() &&
		f.Metadata.IsZero()
}

func (f FSFile) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Always included fields.
	result["path"] = f.Path
	result["base"] = f.Base
	result["actions"] = f.Actions
	result["owner"] = f.Owner
	result["mode"] = f.Mode

	// Omit empty fields.
	if !f.Metadata.IsZero() {
		result["metadata"] = f.Metadata
	}

	return json.Marshal(result)
}

// Flow.

type Flow struct {
	IPVersion   int    `json:"ip_version"`   // IP version.
	Proto       string `json:"proto"`        // Protocol.
	ICMP        ICMP   `json:"icmp"`         // ICMP.
	Local       Node   `json:"local"`        // Local node.
	Remote      Node   `json:"remote"`       // Remote node.
	ServicePort int    `json:"service_port"` // Service port.
	Flags       Flags  `json:"flags"`        // Flags.
	Phase       Phase  `json:"phase"`        // Flow phase.
}

func (f Flow) Clone() Flow {
	return Flow{
		IPVersion:   f.IPVersion,
		Proto:       f.Proto,
		ICMP:        f.ICMP,
		Local:       f.Local.Clone(),
		Remote:      f.Remote.Clone(),
		ServicePort: f.ServicePort,
		Flags:       f.Flags,
		Phase:       f.Phase,
	}
}

func (f Flow) IsZero() bool {
	return f.IPVersion == 0 &&
		f.Proto == "" &&
		f.ICMP.IsZero() &&
		f.Local.IsZero() &&
		f.Remote.IsZero() &&
		f.ServicePort == 0 &&
		f.Flags.IsZero() &&
		f.Phase.IsZero()
}

func (f Flow) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Always included fields.
	result["ip_version"] = f.IPVersion
	result["proto"] = f.Proto

	// Omit empty fields.
	if !f.ICMP.IsZero() {
		result["icmp"] = f.ICMP
	}
	if !f.Local.IsZero() {
		result["local"] = f.Local
	}
	if !f.Remote.IsZero() {
		result["remote"] = f.Remote
	}
	if f.ServicePort != 0 {
		result["service_port"] = f.ServicePort
	}
	if !f.Flags.IsZero() {
		result["flags"] = f.Flags
	}
	if !f.Phase.IsZero() {
		result["phase"] = f.Phase
	}

	return json.Marshal(result)
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

	result := make(map[string]any)

	// Always included fields.
	result["type"] = i.Type
	result["code"] = i.Code

	return json.Marshal(result)
}

type Node struct {
	Address string   `json:"address"` // IP address.
	Name    string   `json:"name"`    // DNS name.
	Names   []string `json:"names"`   // DNS names.
	Port    int      `json:"port"`    // Port.
}

func (n Node) Clone() Node {
	names := make([]string, len(n.Names))
	copy(names, n.Names)
	return Node{
		Address: n.Address,
		Name:    n.Name,
		Names:   names,
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

	result := make(map[string]any)

	// Always included fields.
	result["address"] = n.Address
	result["name"] = n.Name
	result["port"] = n.Port

	// Omit empty fields.
	if len(n.Names) > 0 {
		result["names"] = n.Names
	}

	return json.Marshal(result)
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

	result := make(map[string]any)

	// Always included fields.
	result["ingress"] = f.Ingress
	result["egress"] = f.Egress
	result["incoming"] = f.Incoming
	result["outgoing"] = f.Outgoing
	result["started"] = f.Started
	result["ongoing"] = f.Ongoing
	result["ended"] = f.Ended
	result["terminator"] = f.Terminator
	result["terminated"] = f.Terminated

	return json.Marshal(result)
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

	result := make(map[string]any)

	// Always included fields.
	result["direction"] = p.Direction
	result["initiated_by"] = p.InitatedBy
	result["status"] = p.Status
	result["ended_by"] = p.EndedBy

	return json.Marshal(result)
}

// Flow Aggregate.

type NodePairKey struct {
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
}

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

	result := make(map[string]any)

	if f.IPVersion != 0 {
		result["ip_version"] = f.IPVersion
	}
	if len(f.Protocols) > 0 {
		result["protocols"] = f.Protocols
	}

	return json.Marshal(result)
}

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

	result := make(map[string]any)

	if p.Proto != "" {
		result["proto"] = p.Proto
	}
	if len(p.Pairs) > 0 {
		result["pairs"] = p.Pairs
	}
	if len(p.ICMPs) > 0 {
		result["icmps"] = p.ICMPs
	}

	return json.Marshal(result)
}

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

	result := make(map[string]any)

	if !p.Nodes.IsZero() {
		result["nodes"] = p.Nodes
	}
	if len(p.PortMatrix) > 0 {
		result["port_matrix"] = p.PortMatrix
	}

	return json.Marshal(result)
}

type ProtocolNode struct {
	Address string   `json:"address"` // IP address.
	Name    string   `json:"name"`    // DNS name.
	Names   []string `json:"names"`   // DNS names.
}

func (p ProtocolNode) Clone() ProtocolNode {
	names := make([]string, len(p.Names))
	copy(names, p.Names)
	return ProtocolNode{
		Address: p.Address,
		Name:    p.Name,
		Names:   names,
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

	result := make(map[string]any)

	// Always included fields.
	result["address"] = p.Address

	// Omit empty fields.
	if p.Name != "" {
		result["name"] = p.Name
	}
	if len(p.Names) > 0 {
		result["names"] = p.Names
	}

	return json.Marshal(result)
}

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

	result := make(map[string]any)

	// Always included fields.
	result["local"] = l.Local
	result["remote"] = l.Remote

	return json.Marshal(result)
}

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

	result := make(map[string]any)

	// Always included fields.
	result["src_port"] = p.SrcPort
	result["dst_port"] = p.DstPort

	// Omit empty fields.
	if !p.Phase.IsZero() {
		result["phase"] = p.Phase
	}

	return json.Marshal(result)
}

// Containers and Namespaces.

type ContainerAggregate struct {
	MntNamespaceIDs    []ContainerPair `json:"mnt_namespace_ids"`
	PidNamespaceIDs    []ContainerPair `json:"pid_namespace_ids"`
	UtsNamespaceIDs    []ContainerPair `json:"uts_namespace_ids"`
	IpcNamespaceIDs    []ContainerPair `json:"ipc_namespace_ids"`
	NetNamespaceIDs    []ContainerPair `json:"net_namespace_ids"`
	CgroupNamespaceIDs []ContainerPair `json:"cgroup_namespace_ids"`
	Containers         []Container     `json:"containers"`
}

func (c ContainerAggregate) Clone() ContainerAggregate {
	mnt := make([]ContainerPair, len(c.MntNamespaceIDs))
	copy(mnt, c.MntNamespaceIDs)
	pid := make([]ContainerPair, len(c.PidNamespaceIDs))
	copy(pid, c.PidNamespaceIDs)
	uts := make([]ContainerPair, len(c.UtsNamespaceIDs))
	copy(uts, c.UtsNamespaceIDs)
	ipc := make([]ContainerPair, len(c.IpcNamespaceIDs))
	copy(ipc, c.IpcNamespaceIDs)
	net := make([]ContainerPair, len(c.NetNamespaceIDs))
	copy(net, c.NetNamespaceIDs)
	cgroup := make([]ContainerPair, len(c.CgroupNamespaceIDs))
	copy(cgroup, c.CgroupNamespaceIDs)
	containers := make([]Container, len(c.Containers))
	for i, container := range c.Containers {
		containers[i] = container.Clone()
	}
	return ContainerAggregate{
		MntNamespaceIDs:    mnt,
		PidNamespaceIDs:    pid,
		UtsNamespaceIDs:    uts,
		IpcNamespaceIDs:    ipc,
		NetNamespaceIDs:    net,
		CgroupNamespaceIDs: cgroup,
		Containers:         containers,
	}
}

func (c ContainerAggregate) IsZero() bool {
	return len(c.MntNamespaceIDs) == 0 &&
		len(c.PidNamespaceIDs) == 0 &&
		len(c.UtsNamespaceIDs) == 0 &&
		len(c.IpcNamespaceIDs) == 0 &&
		len(c.NetNamespaceIDs) == 0 &&
		len(c.CgroupNamespaceIDs) == 0 &&
		len(c.Containers) == 0
}

func (c ContainerAggregate) MarshalJSON() ([]byte, error) {
	if c.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Omit empty fields.
	if len(c.MntNamespaceIDs) > 0 {
		result["mnt_namespace_ids"] = c.MntNamespaceIDs
	}
	if len(c.PidNamespaceIDs) > 0 {
		result["pid_namespace_ids"] = c.PidNamespaceIDs
	}
	if len(c.UtsNamespaceIDs) > 0 {
		result["uts_namespace_ids"] = c.UtsNamespaceIDs
	}
	if len(c.IpcNamespaceIDs) > 0 {
		result["ipc_namespace_ids"] = c.IpcNamespaceIDs
	}
	if len(c.NetNamespaceIDs) > 0 {
		result["net_namespace_ids"] = c.NetNamespaceIDs
	}
	if len(c.CgroupNamespaceIDs) > 0 {
		result["cgroup_namespace_ids"] = c.CgroupNamespaceIDs
	}
	if len(c.Containers) > 0 {
		result["containers"] = c.Containers
	}

	return json.Marshal(result)
}

type ContainerPair struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

func (c ContainerPair) GetName() string {
	return c.Name
}

func (c ContainerPair) GetID() string {
	return c.ID
}

func (c ContainerPair) IsZero() bool {
	return c.Name == "" && c.ID == ""
}

func (c ContainerPair) MarshalJSON() ([]byte, error) {
	if c.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Always included fields.
	result["id"] = c.ID

	// Omit empty fields.
	if c.Name != "" {
		result["name"] = c.Name
	}

	return json.Marshal(result)
}

type Mount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Type        string `json:"type"`
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

	result := make(map[string]any)

	// Always included fields.
	result["source"] = m.Source
	result["destination"] = m.Destination
	result["type"] = m.Type

	return json.Marshal(result)
}

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
	CreatedAt    string     `json:"created_at"`    // Creation time, RFC3339 string.
	StartedAt    string     `json:"started_at"`    // Start time, RFC3339 string.
	FinishedAt   string     `json:"finished_at"`   // Finish time, RFC3339 string.
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
	copy(mounts, c.Mounts)
	env := make([]string, len(c.Env))
	copy(env, c.Env)
	cmd := make([]string, len(c.Cmd))
	copy(cmd, c.Cmd)
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
		Env:          env,
		Cmd:          cmd,
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
		c.CreatedAt == "" &&
		c.StartedAt == "" &&
		c.FinishedAt == "" &&
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

	result := make(map[string]any)

	result["id"] = c.ID

	if c.Name != "" {
		result["name"] = c.Name
	}
	if c.HostName != "" {
		result["hostname"] = c.HostName
	}
	if c.ImageID != "" {
		result["image_id"] = c.ImageID
	}
	if c.Image != "" {
		result["image"] = c.Image
	}
	if c.Version != "" {
		result["version"] = c.Version
	}
	if c.Runtime != "" {
		result["runtime"] = c.Runtime
	}
	if c.Driver != "" {
		result["driver"] = c.Driver
	}
	if c.PID != 0 {
		result["pid"] = c.PID
	}
	if c.ExitCode != 0 {
		result["exit_code"] = c.ExitCode
	}
	if c.Status != "" {
		result["status"] = c.Status
	}
	if c.IsAttached {
		result["is_attached"] = c.IsAttached
	}
	if c.Path != "" {
		result["path"] = c.Path
	}
	if c.Cwd != "" {
		result["cwd"] = c.Cwd
	}
	if c.CreatedAt != "" {
		result["created_at"] = c.CreatedAt
	}
	if c.StartedAt != "" {
		result["started_at"] = c.StartedAt
	}
	if c.FinishedAt != "" {
		result["finished_at"] = c.FinishedAt
	}
	if len(c.Mounts) > 0 {
		result["mounts"] = c.Mounts
	}
	if c.NetworkMode != "" {
		result["network_mode"] = c.NetworkMode
	}
	if c.CgroupnsMode != "" {
		result["cgroupns_mode"] = c.CgroupnsMode
	}
	if c.IpcMode != "" {
		result["ipc_mode"] = c.IpcMode
	}
	if c.PidMode != "" {
		result["pid_mode"] = c.PidMode
	}
	if c.UsernsMode != "" {
		result["userns_mode"] = c.UsernsMode
	}
	if c.UTSMode != "" {
		result["uts_mode"] = c.UTSMode
	}
	if len(c.Env) > 0 {
		result["env"] = c.Env
	}
	if len(c.Cmd) > 0 {
		result["cmd"] = c.Cmd
	}
	if !c.Namespaces.IsZero() {
		result["namespaces"] = c.Namespaces
	}

	return json.Marshal(result)
}

//
// Profiling event.
//

// Egress Peer: A single remote peer that supports the egress profile.

type Peer struct {
	Protocol      string        `json:"protocol"`
	LocalAddress  string        `json:"local_address"`
	LocalName     string        `json:"local_name"`
	LocalNames    []string      `json:"local_names"`
	RemoteAddress string        `json:"remote_address"`
	RemoteName    string        `json:"remote_name"`
	RemoteNames   []string      `json:"remote_names"`
	UsedPorts     []PortCommAgg `json:"used_ports"`
	Status        string        `json:"status"`
	Reason        string        `json:"reason"`
	Process       string        `json:"process"`
	Ancestry      []string      `json:"ancestry"`
}

func (ep Peer) Clone() Peer {
	ancestry := make([]string, len(ep.Ancestry))
	copy(ancestry, ep.Ancestry)
	return Peer{
		Protocol:      ep.Protocol,
		LocalAddress:  ep.LocalAddress,
		LocalName:     ep.LocalName,
		LocalNames:    ep.LocalNames,
		RemoteAddress: ep.RemoteAddress,
		RemoteName:    ep.RemoteName,
		RemoteNames:   ep.RemoteNames,
		UsedPorts:     ep.UsedPorts,
		Status:        ep.Status,
		Reason:        ep.Reason,
		Process:       ep.Process,
		Ancestry:      ancestry,
	}
}

func (ep Peer) IsZero() bool {
	return ep.Protocol == "" &&
		ep.LocalName == "" &&
		ep.LocalAddress == "" &&
		ep.RemoteName == "" &&
		len(ep.LocalNames) == 0 &&
		len(ep.RemoteNames) == 0 &&
		ep.RemoteAddress == "" &&
		ep.Status == "" &&
		ep.Reason == "" &&
		ep.Process == "" &&
		len(ep.Ancestry) == 0 &&
		len(ep.UsedPorts) == 0
}

func (ep Peer) MarshalJSON() ([]byte, error) {
	if ep.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Always included fields.
	result["protocol"] = ep.Protocol
	result["local_name"] = ep.LocalName
	result["local_address"] = ep.LocalAddress

	// Omit empty fields.
	if ep.RemoteName != "" {
		result["remote_name"] = ep.RemoteName
	}
	if ep.RemoteAddress != "" {
		result["remote_address"] = ep.RemoteAddress
	}
	if len(ep.LocalNames) > 0 {
		result["local_names"] = ep.LocalNames
	}
	if len(ep.RemoteNames) > 0 {
		result["remote_names"] = ep.RemoteNames
	}
	if len(ep.UsedPorts) > 0 {
		result["used_ports"] = ep.UsedPorts
	}
	if ep.Status != "" {
		result["status"] = ep.Status
	}
	if ep.Reason != "" {
		result["reason"] = ep.Reason
	}
	if ep.Process != "" {
		result["process"] = ep.Process
	}
	if len(ep.Ancestry) > 0 {
		result["ancestry"] = ep.Ancestry
	}

	return json.Marshal(result)
}

// Egress: A collection of egress traffic that supports the profile.

type Egress struct {
	Peers       []Peer   `json:"peers"`
	SeenDomains []string `json:"seen_domains"`
}

func (e Egress) Clone() Egress {
	uniqueDomains := make([]string, len(e.SeenDomains))
	copy(uniqueDomains, e.SeenDomains)
	egressPeers := make([]Peer, len(e.Peers))
	for i, ep := range e.Peers {
		egressPeers[i] = ep.Clone()
	}
	return Egress{
		Peers:       egressPeers,
		SeenDomains: uniqueDomains,
	}
}

func (e Egress) IsZero() bool {
	return len(e.Peers) == 0 &&
		len(e.SeenDomains) == 0
}

func (e Egress) MarshalJSON() ([]byte, error) {
	if e.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Omit empty fields.
	if len(e.Peers) > 0 {
		result["peers"] = e.Peers
	}
	if len(e.SeenDomains) > 0 {
		result["seen_domains"] = e.SeenDomains
	}

	return json.Marshal(result)
}

// NetProfile: A collection of network telemetry that supports the profile.

type NetProfile struct {
	Egress Egress `json:"egress"`
}

func (np NetProfile) Clone() NetProfile {
	return NetProfile{
		Egress: np.Egress.Clone(),
	}
}

func (np NetProfile) IsZero() bool {
	return np.Egress.IsZero()
}

func (np NetProfile) MarshalJSON() ([]byte, error) {
	if np.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Always included field.
	result["egress"] = np.Egress

	return json.Marshal(result)
}

// NetTelemetry: Summary of network telemetry for the profile.

type NetTelemetry struct {
	EgressTotalDomains     uint `json:"egress_total_domains"`
	EgressTotalConnections uint `json:"egress_total_connections"`
}

func (nt NetTelemetry) Clone() NetTelemetry {
	return NetTelemetry{
		EgressTotalDomains:     nt.EgressTotalDomains,
		EgressTotalConnections: nt.EgressTotalConnections,
	}
}

func (nt NetTelemetry) IsZero() bool {
	return nt.EgressTotalDomains == 0 && nt.EgressTotalConnections == 0
}

func (nt NetTelemetry) MarshalJSON() ([]byte, error) {
	if nt.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Always included fields.
	result["egress_total_domains"] = nt.EgressTotalDomains
	result["egress_total_connections"] = nt.EgressTotalConnections

	return json.Marshal(result)
}

// Telemetry: A collection of telemetry data that supports the profile.

type Telemetry struct {
	NetTelemetry NetTelemetry `json:"network_telemetry"`
}

func (t Telemetry) Clone() Telemetry {
	return Telemetry{
		NetTelemetry: t.NetTelemetry.Clone(),
	}
}

func (t Telemetry) IsZero() bool {
	return t.NetTelemetry.IsZero()
}

func (t Telemetry) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Always included field.
	result["network_telemetry"] = t.NetTelemetry

	return json.Marshal(result)
}

// Evidence: A single piece of evidence that supports an assertion.

type Evidence struct {
	Timestamp   string   `json:"timestamp"`
	EventKind   string   `json:"event_kind"`
	Domain      string   `json:"domain"`
	PeerName    string   `json:"peer_name"`
	PeerAddress string   `json:"peer_address"`
	Process     string   `json:"process"`
	Ancestry    []string `json:"ancestry"`
}

func (e Evidence) Clone() Evidence {
	ancestry := make([]string, len(e.Ancestry))
	copy(ancestry, e.Ancestry)
	return Evidence{
		Timestamp:   e.Timestamp,
		EventKind:   e.EventKind,
		Domain:      e.Domain,
		PeerName:    e.PeerName,
		PeerAddress: e.PeerAddress,
		Process:     e.Process,
		Ancestry:    ancestry,
	}
}

func (e Evidence) IsZero() bool {
	return e.Timestamp == "" &&
		e.EventKind == "" &&
		e.Domain == "" &&
		e.PeerName == "" &&
		e.PeerAddress == "" &&
		e.Process == "" &&
		len(e.Ancestry) == 0
}

func (e Evidence) MarshalJSON() ([]byte, error) {
	if e.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Always included fields.
	result["timestamp"] = e.Timestamp
	result["event_kind"] = e.EventKind

	// Omit empty fields.
	if e.Domain != "" {
		result["domain"] = e.Domain
	}
	if e.PeerName != "" {
		result["peer_name"] = e.PeerName
	}
	if e.PeerAddress != "" {
		result["peer_address"] = e.PeerAddress
	}
	if e.Process != "" {
		result["process"] = e.Process
	}
	if len(e.Ancestry) > 0 {
		result["ancestry"] = e.Ancestry
	}

	return json.Marshal(result)
}

// Assertion: A list of evidence that supports the assertion.

type Assertion struct {
	ID        string     `json:"id"`
	EventKind string     `json:"event_kind"`
	Result    string     `json:"result"`
	Details   string     `json:"details"`
	Evidence  []Evidence `json:"evidence"`
}

func (a Assertion) Clone() Assertion {
	evidence := make([]Evidence, len(a.Evidence))
	for i, e := range a.Evidence {
		evidence[i] = e.Clone()
	}
	return Assertion{
		ID:        a.ID,
		EventKind: a.EventKind,
		Result:    a.Result,
		Details:   a.Details,
		Evidence:  evidence,
	}
}

func (a Assertion) IsZero() bool {
	return a.ID == "" &&
		a.EventKind == "" &&
		a.Result == "" &&
		a.Details == "" &&
		len(a.Evidence) == 0
}

func (a Assertion) MarshalJSON() ([]byte, error) {
	if a.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	// Always included fields.
	result["id"] = a.ID
	result["event_kind"] = a.EventKind

	// Omit empty fields.
	if a.Result != "" {
		result["result"] = a.Result
	}
	if a.Details != "" {
		result["details"] = a.Details
	}
	if len(a.Evidence) > 0 {
		result["evidence"] = a.Evidence
	}

	return json.Marshal(result)
}

// Behavior Profile Event.

type Profile struct {
	Base
	Network    NetProfile  `json:"network"`
	Assertions []Assertion `json:"assertions"`
	Telemetry  Telemetry   `json:"telemetry"`
}

func (p Profile) Clone() Profile {
	assertions := make([]Assertion, len(p.Assertions))
	for i, a := range p.Assertions {
		assertions[i] = a.Clone()
	}
	return Profile{
		Base:       p.Base.Clone(),
		Network:    p.Network.Clone(),
		Assertions: assertions,
		Telemetry:  p.Telemetry.Clone(),
	}
}

func (p Profile) IsZero() bool {
	return p.Base.IsZero() &&
		p.Network.IsZero() &&
		len(p.Assertions) == 0 &&
		p.Telemetry.IsZero()
}

func (p Profile) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}

	result := make(map[string]any)

	if !p.Base.IsZero() {
		baseMap, err := p.Base.MarshalJSONMap()
		if err != nil {
			return nil, err
		}
		for k, v := range baseMap {
			result[k] = v
		}
	}

	if !p.Network.IsZero() {
		result["network"] = p.Network
	}
	if len(p.Assertions) > 0 {
		result["assertions"] = p.Assertions
	}
	if !p.Telemetry.IsZero() {
		result["telemetry"] = p.Telemetry
	}

	return json.Marshal(result)
}
