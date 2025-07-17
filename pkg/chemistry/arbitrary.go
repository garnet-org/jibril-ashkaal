package chemistry

import "time"

// ArbitraryConfigItem.

type ArbitraryConfigItem struct {
	Pattern string         // Pattern to match.
	Number  int            // Number to match.
	Numbers []int          // Numbers to match.
	Time    time.Time      // Time to match.
	CIDR    string         // CIDR to match (format: 192.168.0.1/24).
	What    ArbitraryWhat  // What to match.
	Which   ArbitraryWhich // When matching, is it pertinent or not.
	When    ArbitraryWhen  // Bigger, smaller, equal, ...
}

// ArbitraryWhich.

type ArbitraryWhich int

const (
	ArbitraryWhichNone ArbitraryWhich = iota
	ArbitraryPertinent
	ArbitraryIrrelevant
)

func (a ArbitraryWhich) String() string {
	switch a {
	case ArbitraryWhichNone:
		return "None"
	case ArbitraryPertinent:
		return "Pertinent"
	case ArbitraryIrrelevant:
		return "Irrelevant"
	}
	return "Unknown"
}

// ArbitraryWhat.

type ArbitraryWhat int

const (
	None ArbitraryWhat = iota
	TaskUID
	TaskPID
	TaskRetCode
	TaskExe
	TaskComm
	TaskCmd
	TaskArgs
	TaskEnvs
	TaskStart
	TaskExit
	ParentPID
	ParentExe
	ParentComm
	ParentCmd
	ParentArgs
	ParentEnvs
	ParentOrPrevExe
	TaskOrPrevExe
	TaskOrParentExe
	TaskOrParentComm
	TaskOrParentCmd
	TaskOrParentArgs
	TaskOrParentEnvs
	FlowProto
	FlowFamily
	FlowLocal
	FlowRemote
	FlowLocalPorts
	FlowRemotePorts
	FlowAnyPorts
	FlowAnyPeers
	FlowAnyPeersAndPorts
	AnyAncientExe
	AnyAncientCmd
	AnyAncientArgs
	AnyAncientEnvs
)

func (a ArbitraryWhat) String() string {
	switch a {
	case None:
		return "None"
	case TaskUID:
		return "UID"
	case TaskPID:
		return "PID"
	case TaskRetCode:
		return "ReturnCode"
	case TaskExe:
		return "Executable"
	case TaskComm:
		return "Comm"
	case TaskCmd:
		return "Command"
	case TaskArgs:
		return "Args"
	case TaskEnvs:
		return "Envs"
	case TaskStart:
		return "StartTime"
	case TaskExit:
		return "ExitTime"
	case ParentPID:
		return "ParentPID"
	case ParentExe:
		return "ParentExecutable"
	case ParentComm:
		return "ParentComm"
	case ParentCmd:
		return "ParentCommand"
	case ParentArgs:
		return "ParentArgs"
	case ParentEnvs:
		return "ParentEnvs"
	case ParentOrPrevExe:
		return "ParentOrPrevExe"
	case TaskOrPrevExe:
		return "TaskOrPrevExe"
	case TaskOrParentExe:
		return "TaskOrParentExe"
	case TaskOrParentComm:
		return "TaskOrParentComm"
	case TaskOrParentCmd:
		return "TaskOrParentCmd"
	case TaskOrParentArgs:
		return "TaskOrParentArgs"
	case TaskOrParentEnvs:
		return "TaskOrParentEnvs"
	case FlowLocal:
		return "LocalPeer"
	case FlowRemote:
		return "RemotePeer"
	case FlowLocalPorts:
		return "LocalPorts"
	case FlowRemotePorts:
		return "RemotePorts"
	case FlowAnyPorts:
		return "AnyPorts"
	case FlowAnyPeers:
		return "AnyPeers"
	case FlowAnyPeersAndPorts:
		return "AnyPeersAndPorts"
	case AnyAncientExe:
		return "AnyAncientExe"
	case AnyAncientCmd:
		return "AnyAncientCmd"
	case AnyAncientArgs:
		return "AnyAncientArgs"
	case AnyAncientEnvs:
		return "AnyAncientEnvs"
	}
	return "Unknown"
}

// ArbitraryWhen.

type ArbitraryWhen int

const (
	ArbitraryWhenNone ArbitraryWhen = iota
	ArbitrarySmaller
	ArbitraryBigger
	ArbitraryEqual
)

func (a ArbitraryWhen) String() string {
	switch a {
	case ArbitraryWhenNone:
		return "None"
	case ArbitrarySmaller:
		return "Smaller/Before"
	case ArbitraryBigger:
		return "Bigger/After"
	case ArbitraryEqual:
		return "Equal/At"
	}
	return "Unknown"
}

// ArbitraryHow.

type ArbitraryHow int

const (
	ArbitraryHowNone ArbitraryHow = iota
	ArbitraryAND
	ArbitraryOR
)
