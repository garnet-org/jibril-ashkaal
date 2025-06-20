package chemistry

import "fmt"

type TimesKind int

const (
	DetTimesNone            TimesKind = iota
	DetTimesPerExe                    // Amount of detections for a single executable.
	DetTimesPerParentExe              // Amount of detections for a single parent executable.
	DetTimesPerCmd                    // Amount of detections for a single command.
	DetTimesPerProc                   // Amount of detections for a single process.
	DetTimesPerParentProc             // Amount of detections for a single parent process.
	DetTimesTotal                     // Amount of detections for this detection.
	DetTimesPerFullAncestry           // Amount of detections for a single full ancestry.
	DetTimesEnd
)

var kindStr = map[TimesKind]string{
	DetTimesPerExe:          "times_per_exe",
	DetTimesPerParentExe:    "times_per_parent_exe",
	DetTimesPerCmd:          "times_per_cmd",
	DetTimesPerProc:         "times_per_proc",
	DetTimesPerParentProc:   "times_per_parent_proc",
	DetTimesTotal:           "times_in_total",
	DetTimesPerFullAncestry: "times_per_full_ancestry",
}

func (k TimesKind) String() string {
	if s, ok := kindStr[k]; ok {
		return s
	}
	return ""
}

func (k TimesKind) Str(given string) string {
	switch k {
	case DetTimesPerExe:
		return fmt.Sprintf("Last %s for this executable.", given)
	case DetTimesPerParentExe:
		return fmt.Sprintf("Last %s for this parent executable.", given)
	case DetTimesPerCmd:
		return fmt.Sprintf("Last %s for this command.", given)
	case DetTimesPerProc:
		return fmt.Sprintf("Last %s for this process.", given)
	case DetTimesPerParentProc:
		return fmt.Sprintf("Last %s for this parent process.", given)
	case DetTimesTotal:
		return fmt.Sprintf("Last %s.", given)
	case DetTimesPerFullAncestry:
		return fmt.Sprintf("Last %s for the same ancestry.", given)
	default:
		return ""
	}
}
