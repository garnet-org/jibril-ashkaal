package ongoing

import (
	"encoding/json"
)

// All detection events have these fields.

type Base struct {
	UUID       string     `json:"uuid"`                 // The unique ID of the detection.
	Timestamp  string     `json:"timestamp"`            // The timestamp of the detection.
	Note       string     `json:"note,omitempty"`       // A note about the detection.
	Metadata   Metadata   `json:"metadata"`             // The detection metadata.
	Attenuator Attenuator `json:"attenuator,omitempty"` // The attenuator of the detection.
	Score      Score      `json:"score,omitempty"`      // Detection Security Risk Score.
	Background Background `json:"background,omitempty"` // The detection context.
	Scenario   Scenarios  `json:"scenario,omitempty"`   // GitHub, Kubernetes, Host, etc.
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

// Scenarios is a slice of Scenario.

type Scenarios []Scenario

func (s Scenarios) Clone() Scenarios {
	scenarios := make([]Scenario, len(s))
	copy(scenarios, s)
	return scenarios
}

func (s Scenarios) IsZero() bool {
	return len(s) == 0
}

func (s Scenarios) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return []byte("null"), nil
	}
	type Alias Scenarios
	return json.Marshal(Alias(s))
}

// Detection Event Metadata.

type Metadata struct {
	Kind          string `json:"kind"`                    // Detection event class name.
	Name          string `json:"name"`                    // Detection recipe name.
	Format        string `json:"format"`                  // Detection event format.
	Version       string `json:"version"`                 // Detection event format version.
	Description   string `json:"description,omitempty"`   // Detection event description.
	Tactic        string `json:"tactic,omitempty"`        // Detection event MITRE tactic.
	Technique     string `json:"technique,omitempty"`     // Detection event MITRE technique.
	SubTechnique  string `json:"subtechnique,omitempty"`  // Detection event MITRE subtechnique.
	Importance    string `json:"importance,omitempty"`    // Detection event importance.
	Documentation string `json:"documentation,omitempty"` // Detection event documentation.
}

func (m Metadata) Clone() Metadata {
	return m
}

func (m Metadata) IsZero() bool {
	return m.Kind == "" && m.Name == "" && m.Format == "" && m.Version == "" &&
		m.Description == "" && m.Tactic == "" && m.Technique == "" &&
		m.SubTechnique == "" && m.Importance == "" && m.Documentation == ""
}

func (m Metadata) MarshalJSON() ([]byte, error) {
	if m.IsZero() {
		return []byte("null"), nil
	}
	type Alias Metadata
	return json.Marshal(Alias(m))
}

// Security Risk Score.

type Score struct {
	Source        string  `json:"source,omitempty"` // Source and reason of the score.
	Severity      int     `json:"severity"`         // Severity number of the detection (0-100).
	SeverityLevel string  `json:"severity_level"`   // Severity level of the detection (low, medium, high, critical).
	Confidence    float64 `json:"confidence"`       // Confidence percentage of the detection (0.0-1.0).
	RiskScore     float64 `json:"risk_score"`       // Calculated and rounded up risk score of the detection (0.0-100.0).
}

func (s Score) Clone() Score {
	return s
}

func (s Score) IsZero() bool {
	return s.Source == "" && s.Severity == 0 && s.SeverityLevel == "" &&
		s.Confidence == 0 && s.RiskScore == 0
}

func (s Score) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return []byte("null"), nil
	}
	type Alias Score
	return json.Marshal(Alias(s))
}

// Attenuator.

type Attenuator struct {
	AttenuatedBy     string  `json:"attenuated_by"`      // The model that attenuated the detection.
	Interpretation   string  `json:"interpretation"`     // The interpretation of the attenuation.
	Thinking         string  `json:"thinking,omitempty"` // The thinking of the attenuation.
	IsFalsePositive  bool    `json:"is_false_positive"`  // Whether the detection is a false positive.
	NewSeverity      int     `json:"new_severity"`       // The new detection severity after attenuation (0-100).
	NewSeverityLevel string  `json:"new_severity_level"` // The new detection severity level after attenuation (low, medium, high, critical).
	NewConfidence    float64 `json:"new_confidence"`     // The new detection confidence after attenuation (0.0-1.0).
	NewRiskScore     float64 `json:"new_risk_score"`     // The new detection risk score after attenuation (0.0-100.0).
}

func (a Attenuator) Clone() Attenuator {
	return a
}

func (a Attenuator) IsZero() bool {
	return a.AttenuatedBy == "" && a.Interpretation == "" && a.Thinking == "" &&
		!a.IsFalsePositive && a.NewSeverity == 0 && a.NewSeverityLevel == "" &&
		a.NewConfidence == 0 && a.NewRiskScore == 0
}

func (a Attenuator) MarshalJSON() ([]byte, error) {
	if a.IsZero() {
		return []byte("null"), nil
	}
	type Alias Attenuator
	return json.Marshal(Alias(a))
}

// Context.

type Background struct {
	Files      FileAggregate      `json:"files,omitempty"`
	Flows      FlowAggregate      `json:"flows,omitempty"`
	Containers ContainerAggregate `json:"containers,omitempty"`
	Ancestry   []Process          `json:"ancestry,omitempty"`
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
	return b.Files.IsZero() && b.Flows.IsZero() && b.Containers.IsZero() && len(b.Ancestry) == 0
}

func (b Background) MarshalJSON() ([]byte, error) {
	if b.IsZero() {
		return []byte("null"), nil
	}
	type Alias Background
	return json.Marshal(Alias(b))
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

// Process.

type Process struct {
	Start      string     `json:"start"`                 // The start time of the process.
	Exit       string     `json:"exit"`                  // The exit time of the process.
	Code       int        `json:"retcode"`               // The return code of the process.
	UID        uint       `json:"uid"`                   // The user ID of the process.
	Pid        int        `json:"pid"`                   // The process ID.
	Ppid       int        `json:"ppid"`                  // The parent process ID.
	Comm       string     `json:"comm"`                  // The command name.
	Cmd        string     `json:"cmd"`                   // The command.
	Exe        string     `json:"exe"`                   // The executable name.
	Args       string     `json:"args"`                  // The arguments.
	Envs       string     `json:"envs"`                  // The environment variables.
	Loader     string     `json:"loader,omitempty"`      // The loader name.
	PrevExe    string     `json:"prev_exe,omitempty"`    // The previous executable name.
	PrevArgs   string     `json:"prev_args,omitempty"`   // The previous arguments.
	PrevEnvs   string     `json:"prev_envs,omitempty"`   // The previous environment variables.
	PrevLoader string     `json:"prev_loader,omitempty"` // The previous loader name.
	Namespaces Namespaces `json:"namespaces,omitempty"`  // The namespaces.
}

func (p Process) Clone() Process {
	return p
}

func (p Process) IsZero() bool {
	return p.Start == "" && p.Exit == "" && p.Code == 0 && p.UID == 0 && p.Pid == 0 && p.Ppid == 0 &&
		p.Comm == "" && p.Cmd == "" && p.Exe == "" && p.Args == "" && p.Envs == "" && p.Loader == "" &&
		p.PrevExe == "" && p.PrevArgs == "" && p.PrevEnvs == "" && p.PrevLoader == "" && p.Namespaces.IsZero()
}

func (p Process) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}
	type Alias Process
	return json.Marshal(Alias(p))
}

// Namespaces.

type Namespaces struct {
	MNTNs    uint32 `json:"mnt_ns,omitempty"`    // Mount namespace.
	PIDNs    uint32 `json:"pid_ns,omitempty"`    // PID namespace.
	UTSNs    uint32 `json:"uts_ns,omitempty"`    // UTS namespace.
	IPCNs    uint32 `json:"ipc_ns,omitempty"`    // IPC namespace.
	NetNs    uint32 `json:"net_ns,omitempty"`    // Network namespace.
	CgroupNs uint32 `json:"cgroup_ns,omitempty"` // Cgroup namespace.
}

func (n Namespaces) IsZero() bool {
	return n.MNTNs == 0 && n.PIDNs == 0 && n.UTSNs == 0 &&
		n.IPCNs == 0 && n.NetNs == 0 && n.CgroupNs == 0
}

func (n Namespaces) MarshalJSON() ([]byte, error) {
	if n.IsZero() {
		return []byte("null"), nil
	}
	type Alias Namespaces
	return json.Marshal(Alias(n))
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
	return f.Path == "" && f.Dir == "" && f.Base == "" && f.Type == "" &&
		f.Owner.IsZero() && f.Actions.IsZero() && f.Permissions.IsZero() &&
		f.SpecialBits.IsZero() && f.Metadata.IsZero()
}

func (f File) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}
	type Alias File
	return json.Marshal(Alias(f))
}

type FileOwner struct {
	UID uint32 `json:"uid"` // User ID of owner.
	GID uint32 `json:"gid"` // Group ID of owner.
}

func (f FileOwner) IsZero() bool {
	return f.UID == 0 && f.GID == 0
}

func (f FileOwner) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}
	type Alias FileOwner
	return json.Marshal(Alias(f))
}

type FileSpecialBits struct {
	Setuid bool `json:"setuid"` // Setuid bit set.
	Setgid bool `json:"setgid"` // Setgid bit set.
	Sticky bool `json:"sticky"` // Sticky bit set.
}

func (f FileSpecialBits) IsZero() bool {
	return !f.Setuid && !f.Setgid && !f.Sticky
}

func (f FileSpecialBits) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}
	type Alias FileSpecialBits
	return json.Marshal(Alias(f))
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
	return f.Mode == "" && !f.OwnerRead && !f.OwnerWrite && !f.OwnerExec &&
		!f.GroupRead && !f.GroupWrite && !f.GroupExec &&
		!f.OtherRead && !f.OtherWrite && !f.OtherExec
}

func (f FilePermissions) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}
	type Alias FilePermissions
	return json.Marshal(Alias(f))
}

type FileMetadata struct {
	Size     int64  `json:"size"`     // File size in bytes.
	Access   string `json:"access"`   // Last access time.
	Change   string `json:"change"`   // Last modification time.
	Creation string `json:"creation"` // Creation time.
}

func (f FileMetadata) IsZero() bool {
	return f.Size == 0 && f.Access == "" && f.Change == "" && f.Creation == ""
}

func (f FileMetadata) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}
	type Alias FileMetadata
	return json.Marshal(Alias(f))
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
	return len(f.Actions) == 0 && !f.Open && !f.Read && !f.Write && !f.Exec &&
		!f.Create && !f.Unlink && !f.Rename && !f.Link && !f.Truncate &&
		!f.Fsync && !f.Flock && !f.Mmap && !f.Close && !f.Async && !f.Seek
}

func (f FileActions) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}
	type Alias FileActions
	return json.Marshal(Alias(f))
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
	Path  string   `json:"path,omitempty"`  // Absolute path of the directory.
	Base  string   `json:"base,omitempty"`  // Base name of the directory.
	Dirs  []FSDir  `json:"dirs,omitempty"`  // Subdirectories.
	Files []FSFile `json:"files,omitempty"` // Files in this directory.
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
	return f.Path == "" && f.Base == "" && len(f.Dirs) == 0 && len(f.Files) == 0
}

func (f FSDir) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}
	type Alias FSDir
	return json.Marshal(Alias(f))
}

type FSFile struct {
	Path     string       `json:"path,omitempty"`     // Absolute path of the file.
	Base     string       `json:"base,omitempty"`     // Base name of the file.
	Actions  []string     `json:"actions,omitempty"`  // Actions taken on the file.
	Mode     string       `json:"mode,omitempty"`     // File mode.
	Owner    FileOwner    `json:"owner,omitempty"`    // File owner.
	Metadata FileMetadata `json:"metadata,omitempty"` // File metadata.
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
	return f.Path == "" && f.Base == "" && len(f.Actions) == 0 &&
		f.Mode == "" && f.Owner.IsZero() && f.Metadata.IsZero()
}

func (f FSFile) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}
	type Alias FSFile
	return json.Marshal(Alias(f))
}

// Flow.

type Flow struct {
	IPVersion   int    `json:"ip_version"`             // IP version.
	Proto       string `json:"proto"`                  // Protocol.
	ICMP        ICMP   `json:"icmp,omitempty"`         // ICMP.
	Local       Node   `json:"local"`                  // Local node.
	Remote      Node   `json:"remote"`                 // Remote node.
	ServicePort int    `json:"service_port,omitempty"` // Service port.
	Flags       Flags  `json:"flags,omitempty"`        // Flags.
	Phase       Phase  `json:"phase,omitempty"`        // Flow phase.
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
	return f.IPVersion == 0 && f.Proto == "" && f.ICMP.IsZero() &&
		f.Local.IsZero() && f.Remote.IsZero() && f.ServicePort == 0 &&
		f.Flags.IsZero() && f.Phase.IsZero()
}

func (f Flow) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}
	type Alias Flow
	return json.Marshal(Alias(f))
}

type ICMP struct {
	Type string `json:"type,omitempty"` // ICMP type.
	Code string `json:"code,omitempty"` // ICMP code.
}

func (i ICMP) IsZero() bool {
	return i.Type == "" && i.Code == ""
}

func (i ICMP) MarshalJSON() ([]byte, error) {
	if i.IsZero() {
		return []byte("null"), nil
	}
	type Alias ICMP
	return json.Marshal(Alias(i))
}

type Node struct {
	Address string   `json:"address,omitempty"` // IP address.
	Name    string   `json:"name,omitempty"`    // DNS name.
	Names   []string `json:"names,omitempty"`   // DNS names.
	Port    int      `json:"port,omitempty"`    // Port.
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
	return n.Address == "" && n.Name == "" && len(n.Names) == 0 && n.Port == 0
}

func (n Node) MarshalJSON() ([]byte, error) {
	if n.IsZero() {
		return []byte("null"), nil
	}
	type Alias Node
	return json.Marshal(Alias(n))
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
	return !f.Ingress && !f.Egress && !f.Incoming && !f.Outgoing &&
		!f.Started && !f.Ongoing && !f.Ended && !f.Terminator && !f.Terminated
}

func (f Flags) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return []byte("null"), nil
	}
	type Alias Flags
	return json.Marshal(Alias(f))
}

type Phase struct {
	Direction  string `json:"direction,omitempty"`    // Direction of the flow.
	InitatedBy string `json:"initiated_by,omitempty"` // Who initiated the flow.
	Status     string `json:"status,omitempty"`       // Status of the flow.
	EndedBy    string `json:"ended_by,omitempty"`     // Who ended the flow.
}

func (p Phase) IsZero() bool {
	return p.Direction == "" && p.InitatedBy == "" && p.Status == "" && p.EndedBy == ""
}

func (p Phase) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}
	type Alias Phase
	return json.Marshal(Alias(p))
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
	type Alias FlowAggregate
	return json.Marshal(Alias(f))
}

type ProtocolAggregate struct {
	Proto string                   `json:"proto"`           // Protocol (e.g., TCP, UDP, ICMP).
	Pairs []ProtocolLocalRemoteAgg `json:"pairs,omitempty"` // List of unique local/remote node pairs for this protocol.
	ICMPs []ICMP                   `json:"icmps,omitempty"` // ICMP types/codes if protocol is ICMP.
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

type ProtocolLocalRemoteAgg struct {
	Nodes      LocalRemotePair `json:"nodes"`                 // Local and remote nodes.
	PortMatrix []PortCommAgg   `json:"port_matrix,omitempty"` // All port communications between these nodes.
}

func (p ProtocolLocalRemoteAgg) Clone() ProtocolLocalRemoteAgg {
	portMatrix := make([]PortCommAgg, len(p.PortMatrix))
	copy(portMatrix, p.PortMatrix)
	return ProtocolLocalRemoteAgg{
		Nodes:      p.Nodes.Clone(),
		PortMatrix: portMatrix,
	}
}

type ProtocolNode struct {
	Address string   `json:"address"`         // IP address.
	Name    string   `json:"name"`            // DNS name.
	Names   []string `json:"names,omitempty"` // DNS names.
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

type PortCommAgg struct {
	SrcPort int   `json:"src_port,omitempty"` // Source port.
	DstPort int   `json:"dst_port,omitempty"` // Destination port.
	Phase   Phase `json:"phase,omitempty"`    // Flow phase.
}

// Containers and Namespaces

type ContainerAggregate struct {
	MntNamespaceIDs    []ContainerPair `json:"mnt_namespace_ids,omitempty"`
	PidNamespaceIDs    []ContainerPair `json:"pid_namespace_ids,omitempty"`
	UtsNamespaceIDs    []ContainerPair `json:"uts_namespace_ids,omitempty"`
	IpcNamespaceIDs    []ContainerPair `json:"ipc_namespace_ids,omitempty"`
	NetNamespaceIDs    []ContainerPair `json:"net_namespace_ids,omitempty"`
	CgroupNamespaceIDs []ContainerPair `json:"cgroup_namespace_ids,omitempty"`
	Containers         []Container     `json:"containers,omitempty"`
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
	return len(c.MntNamespaceIDs) == 0 && len(c.PidNamespaceIDs) == 0 &&
		len(c.UtsNamespaceIDs) == 0 && len(c.IpcNamespaceIDs) == 0 &&
		len(c.NetNamespaceIDs) == 0 && len(c.CgroupNamespaceIDs) == 0 &&
		len(c.Containers) == 0
}

func (c ContainerAggregate) MarshalJSON() ([]byte, error) {
	if c.IsZero() {
		return []byte("null"), nil
	}
	type Alias ContainerAggregate
	return json.Marshal(Alias(c))
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

type Mount struct {
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	Type        string `json:"type,omitempty"`
}

type Container struct {
	ID           string     `json:"id"`                      // Container ID.
	Name         string     `json:"name,omitempty"`          // Container name.
	HostName     string     `json:"hostname,omitempty"`      // Host name.
	ImageID      string     `json:"image_id,omitempty"`      // Image ID.
	Image        string     `json:"image,omitempty"`         // Image name.
	Version      string     `json:"version,omitempty"`       // Image version.
	Runtime      string     `json:"runtime,omitempty"`       // Container runtime ("docker", "containerd", etc).
	Driver       string     `json:"driver,omitempty"`        // Container driver ("overlay2", "aufs", etc).
	PID          int        `json:"pid,omitempty"`           // Process ID.
	ExitCode     int        `json:"exit_code,omitempty"`     // Exit code.
	Status       string     `json:"status,omitempty"`        // Current status.
	IsAttached   bool       `json:"is_attached,omitempty"`   // Whether the container is attached to the host.
	Path         string     `json:"path,omitempty"`          // Path to the container executable.
	Cwd          string     `json:"cwd,omitempty"`           // Current working directory.
	CreatedAt    string     `json:"created_at,omitempty"`    // Creation time, RFC3339 string.
	StartedAt    string     `json:"started_at,omitempty"`    // Start time, RFC3339 string.
	FinishedAt   string     `json:"finished_at,omitempty"`   // Finish time, RFC3339 string.
	Mounts       []Mount    `json:"mounts,omitempty"`        // Mounts.
	NetworkMode  string     `json:"network_mode,omitempty"`  // Network mode.
	CgroupnsMode string     `json:"cgroupns_mode,omitempty"` // Cgroup namespace mode.
	IpcMode      string     `json:"ipc_mode,omitempty"`      // IPC mode.
	PidMode      string     `json:"pid_mode,omitempty"`      // PID mode.
	UsernsMode   string     `json:"userns_mode,omitempty"`   // User namespace mode.
	UTSMode      string     `json:"uts_mode,omitempty"`      // UTS namespace mode.
	Env          []string   `json:"env,omitempty"`           // Environment variables.
	Cmd          []string   `json:"cmd,omitempty"`           // Command.
	Namespaces   Namespaces `json:"namespaces,omitempty"`    // Namespaces.
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
