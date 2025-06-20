package chemistry

import "fmt"

// FlowActionSide.

type FlowActionSide uint64

const (
	FlowActionSideNone   FlowActionSide = iota // Nothing.
	FlowActionSideLocal                        // Local node.
	FlowActionSideRemote                       // Remote node.
	FlowActionSideBoth                         // Both nodes.
)

func (fa FlowActionSide) String() string {
	value := uint64(fa)
	switch value {
	case 0:
		return ""
	case 1:
		return "local"
	case 2:
		return "remote"
	case 3:
		return "both"
	}
	return "unknown"
}

// FlowActionDirection.

type FlowActionDirection uint64

const (
	FlowActionDirectionNone    FlowActionDirection = iota // Nothing.
	FlowActionDirectionIngress                            // Packets received.
	FlowActionDirectionEgress                             // Packets sent.
	FlowActionDirectionBoth
)

func (fa FlowActionDirection) String() string {
	value := uint64(fa)
	switch value {
	case 0:
		return ""
	case 1:
		return "ingress"
	case 2:
		return "egress"
	case 3:
		return "both"
	}
	return "unknown"
}

// FlowActionStatus.

type FlowActionStatus uint64

const (
	FlowActionStatusNone    FlowActionStatus = iota // Nothing.
	FlowActionStatusOngoing                         // Flow is established.
	FlowActionStatusStarted                         // Flow is started.
	FlowActionStatusEnded                           // Flow has ended.
)

func (fa FlowActionStatus) String() string {
	value := uint64(fa)
	switch value {
	case 0:
		return ""
	case 1:
		return "ongoing"
	case 2:
		return "started"
	case 3:
		return "ended"
	}
	return "unknown"
}

// FlowActionHow.

type FlowActionHow int

const (
	FlowActionHowNone FlowActionHow = iota
	FlowActionHowAny
	FlowActionHowAll
	FlowActionHowEnd
)

func (f FlowActionHow) String() string {
	switch f {
	case FlowActionHowAny:
		return "any"
	case FlowActionHowAll:
		return "all"
	default:
		return "none"
	}
}

// FlowAction.

type FlowAction uint64

const (
	FlowActionNone       FlowAction = 0               // Nothing.
	FlowActionCreated    FlowAction = 1 << (iota - 1) // Not much to say about the flow.
	FlowActionIngress                                 // Packets received.
	FlowActionEgress                                  // Packets sent.
	FlowActionIncoming                                // Remote node initiated.
	FlowActionOutgoing                                // Local node initiated.
	FlowActionOngoing                                 // Flow is established.
	FlowActionStarted                                 // Flow is started.
	FlowActionEnded                                   // Flow has ended.
	FlowActionTerminator                              // Locally terminated.
	FlowActionTerminated                              // Remotely terminated.
	FlowActionEnd                                     // Nothing.
)

var flowActionStrings = []string{
	"created",
	"ingress",
	"egress",
	"incoming",
	"outgoing",
	"ongoing",
	"started",
	"ended",
	"terminator",
	"terminated",
}

func (fa FlowAction) String() string {
	value := uint64(fa)
	if value == 0 {
		return ""
	}
	str := ""
	for i := 0; i < len(flowActionStrings); i++ {
		if value&(1<<i) != 0 {
			if str != "" {
				str += "|"
			}
			str += flowActionStrings[i]
		}
	}
	return str
}

func (fa FlowAction) NewString() string {
	if uint64(fa) == 0 {
		return ""
	}
	return fmt.Sprintf("%s|%s|%s|%s",
		fa.Direction().String(),
		fa.InitiatedBy().String(),
		fa.Status().String(),
		fa.EndedBy().String(),
	)
}

func (fa FlowAction) HasAction(action FlowAction) bool {
	return fa&action != 0
}

func (fa FlowAction) Direction() FlowActionDirection {
	switch {
	case fa.HasAction(FlowActionIngress) && fa.HasAction(FlowActionEgress):
		return FlowActionDirectionBoth
	case fa.HasAction(FlowActionIngress):
		return FlowActionDirectionIngress
	case fa.HasAction(FlowActionEgress):
		return FlowActionDirectionEgress
	}
	return FlowActionDirectionNone
}

func (fa FlowAction) InitiatedBy() FlowActionSide {
	switch {
	case fa.HasAction(FlowActionIncoming) && fa.HasAction(FlowActionOutgoing):
		return FlowActionSideBoth
	case fa.HasAction(FlowActionIncoming):
		return FlowActionSideRemote
	case fa.HasAction(FlowActionOutgoing):
		return FlowActionSideLocal
	}
	return FlowActionSideNone
}

func (fa FlowAction) Status() FlowActionStatus {
	switch {
	case fa.HasAction(FlowActionEnded):
		return FlowActionStatusEnded
	case fa.HasAction(FlowActionOngoing):
		return FlowActionStatusOngoing
	case fa.HasAction(FlowActionStarted):
		return FlowActionStatusStarted
	}
	return FlowActionStatusNone
}

func (fa FlowAction) EndedBy() FlowActionSide {
	switch {
	case fa.HasAction(FlowActionTerminator) && fa.HasAction(FlowActionTerminated):
		return FlowActionSideBoth
	case fa.HasAction(FlowActionTerminator):
		return FlowActionSideLocal
	case fa.HasAction(FlowActionTerminated):
		return FlowActionSideRemote
	}
	return FlowActionSideNone
}

func (fa FlowAction) Failed() bool {
	return fa == FlowActionNone
}
