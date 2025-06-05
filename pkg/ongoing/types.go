package ongoing

// All detection events have these fields.

type Base struct {
	UUID       string      `json:"uuid"`                 // The unique ID of the detection.
	Timestamp  string      `json:"timestamp"`            // The timestamp of the detection.
	Note       string      `json:"note,omitempty"`       // A note about the detection.
	Metadata   *Metadata   `json:"metadata"`             // The detection metadata (Previous Head).
	Attenuator *Attenuator `json:"attenuator,omitempty"` // The attenuator of the detection.
	Background *Background `json:"background,omitempty"` // The detection context (Previous Body).
	Habitat    *Habitat    `json:"habitat,omitempty"`    // The detection habitat.
	Scenario   []Scenario  `json:"scenario,omitempty"`   // GitHub, Kubernetes, Host, etc.
}

func (b *Base) SetMetadata(metadata *Metadata) {
	b.Metadata = metadata
}

func (b *Base) SetAttenuator(attenuator *Attenuator) {
	b.Attenuator = attenuator
}

func (b *Base) SetBackground(background *Background) {
	b.Background = background
}

func (b *Base) SetHabitat(habitat *Habitat) {
	b.Habitat = habitat
}

func (b *Base) AddScenario(scenario Scenario) {
	b.Scenario = append(b.Scenario, scenario)
}

func (b *Base) Clone() *Base {
	return &Base{
		UUID:       b.UUID,
		Timestamp:  b.Timestamp,
		Note:       b.Note,
		Metadata:   b.Metadata,
		Attenuator: b.Attenuator,
		Background: b.Background,
		Habitat:    b.Habitat,
		Scenario:   nil,
	}
}

// Detection Event Metadata.

type Metadata struct {
	Kind          string `json:"kind"`                    // Detection event class name.
	Name          string `json:"name"`                    // Detection recipe name.
	Format        string `json:"format"`                  // Detection event format.
	Version       string `json:"version"`                 // Detection event format version.
	Description   string `json:"description,omitempty"`   // Detection event description.
	Importance    string `json:"importance,omitempty"`    // Detection event importance.
	Documentation string `json:"documentation,omitempty"` // Detection event documentation.
	Tactic        string `json:"tactic,omitempty"`        // Detection event MITRE tactic.
	Technique     string `json:"technique,omitempty"`     // Detection event MITRE technique.
	SubTechnique  string `json:"subtechnique,omitempty"`  // Detection event MITREsubtechnique.
}

// Attenuator.

type Attenuator struct {
	IsFalsePositive bool   `json:"is_false_positive"`   // Whether the detection is a false positive.
	NewImportance   string `json:"new_importance"`      // The new detection importance after attenuation.
	Interpretation  string `json:"interpretation"`      // The interpretation of the attenuation.
	Reasoning       string `json:"reasoning,omitempty"` // The reasoning behind the attenuation.
	AttenuatedBy    string `json:"attenuated_by"`       // The model that attenuated the detection.
}

// Context.

type Background struct {
	Files    *FileAggregate `json:"files,omitempty"`
	Flows    *FlowAggregate `json:"flows,omitempty"`
	Ancestry []Process      `json:"ancestry,omitempty"`
}

func (b *Background) SetFiles(files *FileAggregate) {
	b.Files = files
}

func (b *Background) SetFlows(flows *FlowAggregate) {
	b.Flows = flows
}

func (b *Background) AddAncestry(ancestry Process) {
	b.Ancestry = append(b.Ancestry, ancestry)
}

// File Access Detection Event.

type FileAccess struct {
	*Base
	File File `json:"file"`
}

func (f *FileAccess) Clone() *FileAccess {
	return &FileAccess{
		Base: f.Base.Clone(),
		File: f.File,
	}
}

// Execution Detection Event.

type Execution struct {
	*Base
	Process Process `json:"process"`
}

func (e *Execution) Clone() *Execution {
	return &Execution{
		Base:    e.Base.Clone(),
		Process: e.Process,
	}
}

// Network Peers Detection Event.

type NetworkPeer struct {
	*Base
	Flow Flow `json:"flow"`
}

func (n *NetworkPeer) Clone() NetworkPeer {
	return NetworkPeer{
		Base: n.Base.Clone(),
		Flow: n.Flow,
	}
}

// Network Flow Event.

type NetworkFlow struct {
	*Base
	Flow Flow `json:"flow"`
}

// Drop IP Detection Event.

type DropIP struct {
	*Base
	IP   string `json:"ip"`   // The IP that was dropped.
	Flow Flow   `json:"flow"` // The flow that triggered the drop.
}

func (d *DropIP) Clone() *DropIP {
	return &DropIP{
		Base: d.Base.Clone(),
		IP:   d.IP,
		Flow: d.Flow,
	}
}

// Drop Domain Detection Event.

type DropDomain struct {
	*Base
	Domain string `json:"domain"` // The dropped resolution domain.
	Flow   Flow   `json:"flow"`   // The resolution flow.
}

func (d *DropDomain) Clone() *DropDomain {
	return &DropDomain{
		Base:   d.Base.Clone(),
		Domain: d.Domain,
		Flow:   d.Flow,
	}
}

// Process.

type Process struct {
	Start      string `json:"start"`                 // The start time of the process.
	Exit       string `json:"exit"`                  // The exit time of the process.
	Code       int    `json:"retcode"`               // The return code of the process.
	UID        uint   `json:"uid"`                   // The user ID of the process.
	Pid        int    `json:"pid"`                   // The process ID.
	Ppid       int    `json:"ppid"`                  // The parent process ID.
	Comm       string `json:"comm"`                  // The command name.
	Cmd        string `json:"cmd"`                   // The command.
	Exe        string `json:"exe"`                   // The executable name.
	Args       string `json:"args"`                  // The arguments.
	Loader     string `json:"loader,omitempty"`      // The loader name.
	PrevExe    string `json:"prev_exe,omitempty"`    // The previous executable name.
	PrevArgs   string `json:"prev_args,omitempty"`   // The previous arguments.
	PrevLoader string `json:"prev_loader,omitempty"` // The previous loader name.
}

// File.

type File struct {
	File     string `json:"file"`     // The absolute path to the file.
	Dir      string `json:"dir"`      // The directory of the file.
	Base     string `json:"basename"` // The base name of the file.
	Actions  string `json:"actions"`  // The actions that have been performed on the file.
	Fasync   bool   `json:"fasync"`   // An async I/O has been performed on the file.
	Flock    bool   `json:"flock"`    // A flock has been performed on the file.
	Fsync    bool   `json:"fsync"`    // A fsync has been performed on the file.
	Llseek   bool   `json:"llseek"`   // A llseek has been performed on the file.
	Mmap     bool   `json:"mmap"`     // A mmap has been performed on the file.
	Open     bool   `json:"open"`     // A open has been performed on the file.
	Read     bool   `json:"read"`     // A read has been performed on the file.
	Write    bool   `json:"write"`    // A write has been performed on the file.
	Rename   bool   `json:"rename"`   // A rename has been performed on the file.
	Truncate bool   `json:"truncate"` // A truncate has been performed on the file.
	Unlink   bool   `json:"unlink"`   // A unlink has been performed on the file.
	Create   bool   `json:"create"`   // A create has been performed on the file.
	Close    bool   `json:"close"`    // A close has been performed on the file.
	Link     bool   `json:"link"`     // A link has been performed on the file.
	Execve   bool   `json:"execve"`   // A execve has been performed on the file.
}

// File Aggregates.

type FileAggregate struct {
	Root *FSDir `json:"root"` // Root directory of the file tree.
}

type FSDir struct {
	AbsPath  string   `json:"abs_path,omitempty"`  // Absolute path of the directory.
	BaseName string   `json:"base_name,omitempty"` // Base name of the directory.
	Dirs     []FSDir  `json:"dirs,omitempty"`      // Subdirectories.
	Files    []FSFile `json:"files,omitempty"`     // Files in this directory.
}

type FSFile struct {
	AbsPath  string   `json:"abs_path,omitempty"`  // Absolute path of the file.
	BaseName string   `json:"base_name,omitempty"` // Base name of the file.
	Actions  []string `json:"actions,omitempty"`   // Actions taken on the file.
}

// Flow.

type Flow struct {
	IPVersion   int    `json:"ip_version"`             // IP version.
	Proto       string `json:"proto"`                  // Protocol.
	ICMP        *ICMP  `json:"icmp,omitempty"`         // ICMP.
	Local       Node   `json:"local"`                  // Local node.
	Remote      Node   `json:"remote"`                 // Remote node.
	ServicePort int    `json:"service_port,omitempty"` // Service port.
	Flags       *Flags `json:"flags,omitempty"`        // Flags.
	Phase       *Phase `json:"phase,omitempty"`        // Flow phase.
}

type ICMP struct {
	Type string `json:"type,omitempty"` // ICMP type.
	Code string `json:"code,omitempty"` // ICMP code.
}

type Node struct {
	Address string   `json:"address,omitempty"` // IP address.
	Name    string   `json:"name,omitempty"`    // DNS name.
	Names   []string `json:"names,omitempty"`   // DNS names.
	Port    int      `json:"port,omitempty"`    // Port.
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

type Phase struct {
	Direction  string `json:"direction,omitempty"`    // Direction of the flow.
	InitatedBy string `json:"initiated_by,omitempty"` // Who initiated the flow.
	Status     string `json:"status,omitempty"`       // Status of the flow.
	EndedBy    string `json:"ended_by,omitempty"`     // Who ended the flow.
}

// Flow Aggregates.

type NodePairKey struct {
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
}

type FlowAggregate struct {
	IPVersion int                 `json:"ip_version"` // IP version.
	Protocols []ProtocolAggregate `json:"protocols"`  // List of protocol aggregates.
}

type ProtocolAggregate struct {
	Proto string                   `json:"proto"`           // Protocol (e.g., TCP, UDP, ICMP).
	Pairs []ProtocolLocalRemoteAgg `json:"pairs,omitempty"` // List of unique local/remote node pairs for this protocol.
	ICMPs []ICMP                   `json:"icmps,omitempty"` // ICMP types/codes if protocol is ICMP.
}

type ProtocolLocalRemoteAgg struct {
	Nodes      LocalRemotePair `json:"nodes"`                 // Local and remote nodes.
	PortMatrix []PortCommAgg   `json:"port_matrix,omitempty"` // All port communications between these nodes.
}

type ProtocolNode struct {
	Address string   `json:"address"`         // IP address.
	Name    string   `json:"name"`            // DNS name.
	Names   []string `json:"names,omitempty"` // DNS names.
}

type LocalRemotePair struct {
	Local  ProtocolNode `json:"local"`  // Local node.
	Remote ProtocolNode `json:"remote"` // Remote node.
}

type PortCommAgg struct {
	SrcPort int    `json:"src_port,omitempty"` // Source port.
	DstPort int    `json:"dst_port,omitempty"` // Destination port.
	Phase   *Phase `json:"phase,omitempty"`    // Flow phase.
}

// Habitat.

type Habitat struct {
	Distro       *Distro      `json:"distro,omitempty"`       // Linux distribution.
	Executable   *Executable  `json:"executable,omitempty"`   // Executable.
	Dependencies []Dependency `json:"dependencies,omitempty"` // Dependencies.
	Python       *Python      `json:"python,omitempty"`       // Python.
}

type Distro struct {
	Name    string `json:"name,omitempty"`    // Name.
	Version string `json:"version,omitempty"` // Version.
	Flavor  string `json:"flavor,omitempty"`  // Flavor.
}

type Executable struct {
	Path              string   `json:"path,omitempty"`                // Path.
	Interpreter       string   `json:"interpreter,omitempty"`         // Interpreter.
	Package           *Package `json:"package,omitempty"`             // Package.
	IsELF             bool     `json:"is_elf,omitempty"`              // Is ELF binary ?
	IsStatic          bool     `json:"is_static,omitempty"`           // Is static binary ?
	IsDynamic         bool     `json:"is_dynamic,omitempty"`          // Is dynamic binary ?
	IsScript          bool     `json:"is_script,omitempty"`           // Is script ?
	IsSupportedScript bool     `json:"is_supported_script,omitempty"` // Is supported script ?
	ScriptType        string   `json:"script_type,omitempty"`         // Script type (e.g., "bash", "python", etc.).
}

type Package struct {
	Name    string `json:"name,omitempty"`    // Name.
	Version string `json:"version,omitempty"` // Version.
}

type Dependency struct {
	Name    string   `json:"name,omitempty"`    // Name.
	Version string   `json:"version,omitempty"` // Version.
	Files   []string `json:"files,omitempty"`   // Files.
}

type Python struct {
	Stdlib     []PythonModule `json:"stdlib,omitempty"`     // Standard library.
	ThirdParty []PythonModule `json:"thirdparty,omitempty"` // Third party.
}

type PythonModule struct {
	Name    string `json:"name,omitempty"`    // Name.
	Version string `json:"version,omitempty"` // Version.
}
