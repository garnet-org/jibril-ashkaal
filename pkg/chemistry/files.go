package chemistry

// FileActionHow.

type FileActionHow int

const (
	FileActionHowNone FileActionHow = iota
	FileActionHowAny
	FileActionHowAll
	FileActionHowEnd
)

func (f FileActionHow) String() string {
	switch f {
	case FileActionHowAny:
		return "any"
	case FileActionHowAll:
		return "all"
	default:
		return "none"
	}
}

// FileAction.

type FileAction uint64

const (
	FileActionNone     FileAction = 0
	FileActionFasync   FileAction = 1 << 0
	FileActionFlock    FileAction = 1 << 1
	FileActionFsync    FileAction = 1 << 2
	FileActionLlseek   FileAction = 1 << 3
	FileActionMmap     FileAction = 1 << 4
	FileActionOpen     FileAction = 1 << 5
	FileActionRead     FileAction = 1 << 6
	FileActionWrite    FileAction = 1 << 7
	FileActionRename   FileAction = 1 << 8
	FileActionTruncate FileAction = 1 << 9
	FileActionUnlink   FileAction = 1 << 10
	FileActionCreate   FileAction = 1 << 11
	FileActionClose    FileAction = 1 << 12
	FileActionLink     FileAction = 1 << 13
	FileActionExecve   FileAction = 1 << 14
	FileActionEnd      FileAction = 1 << 15
)

const (
	FileActionsNone FileAction = 0
	FileActionsAny  FileAction = 0 |
		FileActionFasync |
		FileActionFlock |
		FileActionFsync |
		FileActionLlseek |
		FileActionMmap |
		FileActionOpen |
		FileActionRead |
		FileActionWrite |
		FileActionRename |
		FileActionTruncate |
		FileActionUnlink |
		FileActionCreate |
		FileActionClose |
		FileActionLink |
		FileActionExecve
	FileActionsOpen FileAction = 0 |
		FileActionOpen |
		FileActionClose
	FileActionsRead FileAction = 0 |
		FileActionRead |
		FileActionLlseek |
		FileActionMmap
	FileActionsModify FileAction = 0 |
		FileActionCreate |
		FileActionLink |
		FileActionWrite |
		FileActionTruncate |
		FileActionFsync |
		FileActionRename |
		FileActionUnlink
	FileActionsAccess FileAction = 0 |
		FileActionOpen | // ActionsOpen.
		FileActionClose |
		FileActionRead | // ActionsRead.
		FileActionLlseek |
		FileActionMmap |
		FileActionCreate | // ActionsModify.
		FileActionLink |
		FileActionWrite |
		FileActionTruncate |
		FileActionFsync |
		FileActionRename |
		FileActionUnlink
	FileActionsAccessNoMmap FileAction = 0 |
		FileActionOpen | // ActionsOpen.
		FileActionClose |
		FileActionRead | // ActionsRead (without mmap).
		FileActionLlseek |
		FileActionCreate | // ActionsModify.
		FileActionLink |
		FileActionWrite |
		FileActionTruncate |
		FileActionFsync |
		FileActionRename |
		FileActionUnlink
	FileActionsTamper FileAction = 0 |
		FileActionLink |
		FileActionUnlink |
		FileActionTruncate |
		FileActionRename
)

// revive:disable

var fileActionStrings = []string{
	"fasync",
	"flock",
	"fsync",
	"llseek",
	"mmap",
	"open",
	"read",
	"write",
	"rename",
	"truncate",
	"unlink",
	"create",
	"close",
	"link",
	"execve",
}

var FileActionsMacros = map[string]FileAction{
	"any":                    FileActionsAny,
	"open_related":           FileActionsOpen,
	"read_related":           FileActionsRead,
	"modify_related":         FileActionsModify,
	"access_related":         FileActionsAccess,
	"access_no_mmap_related": FileActionsAccessNoMmap,
	"tamper_related":         FileActionsTamper,
}

var FileActionsMacrosToStrings = map[FileAction]string{
	FileActionsAny:          "any",
	FileActionsOpen:         "open_related",
	FileActionsRead:         "read_related",
	FileActionsModify:       "modify_related",
	FileActionsAccess:       "access_related",
	FileActionsAccessNoMmap: "access_no_mmap_related",
	FileActionsTamper:       "tamper_related",
}

var FileActions = map[string]FileAction{
	"fasync|flock|fsync|llseek|mmap|open|read|write|rename|truncate|unlink|create|close|link|execve": FileActionsAny,
	"open|close":       FileActionsOpen,
	"read|llseek|mmap": FileActionsRead,
	"create|link|write|truncate|fsync|rename|unlink":                             FileActionsModify,
	"open|close|read|llseek|mmap|create|link|write|truncate|fsync|rename|unlink": FileActionsAccess,
	"open|close|read|llseek|create|link|write|truncate|fsync|rename|unlink":      FileActionsAccessNoMmap,
	"link|unlink|truncate|rename":                                                FileActionsTamper,
}

var FileActionsToStrings = map[FileAction]string{
	FileActionsAny:          "fasync|flock|fsync|llseek|mmap|open|read|write|rename|truncate|unlink|create|close|link|execve",
	FileActionsOpen:         "open|close",
	FileActionsRead:         "read|llseek|mmap",
	FileActionsModify:       "create|link|write|truncate|fsync|rename|unlink",
	FileActionsAccess:       "open|close|read|llseek|mmap|create|link|write|truncate|fsync|rename|unlink",
	FileActionsAccessNoMmap: "open|close|read|llseek|create|link|write|truncate|fsync|rename|unlink",
	FileActionsTamper:       "link|unlink|truncate|rename",
}

// revive:enable

// Methods.

func (fa FileAction) String() string {
	value := uint64(fa)

	if value == 0 {
		return "none"
	}

	// Check if the value is a valid FileActions (actions macro).
	str, ok := FileActionsToStrings[fa]
	if ok {
		return str
	}

	str = ""

	// Check if the value is a valid FileAction (concatenation of individual actions).
	for i := 0; i < len(fileActionStrings); i++ {
		if value&(1<<i) != 0 {
			if str != "" {
				str += "|"
			}
			str += fileActionStrings[i]
		}
	}

	return str
}

func (fa FileAction) HasAction(action FileAction) bool {
	return fa&action != 0
}

func (fa FileAction) Failed() bool {
	return fa == FileActionNone
}
