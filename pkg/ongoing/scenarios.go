package ongoing

import (
	"encoding/json"
	"strconv"
	"time"
)

type Scenario interface {
	Type() string
	Clone() Scenario
	IsZero() bool
}

// Scenario GitHub.

type ScenarioGitHub struct {
	ID                string    `json:"id"`
	Action            string    `json:"action"`
	Actor             string    `json:"actor"`
	ActorID           string    `json:"actor_id"`
	EventName         string    `json:"event_name"`
	Job               string    `json:"job"`
	Ref               string    `json:"ref"`
	RefName           string    `json:"ref_name"`
	RefProtected      bool      `json:"ref_protected"`
	RefType           string    `json:"ref_type"`
	Repository        string    `json:"repository"`
	RepositoryID      string    `json:"repository_id"`
	RepositoryOwner   string    `json:"repository_owner"`
	RepositoryOwnerID string    `json:"repository_owner_id"`
	RunAttempt        string    `json:"run_attempt"`
	RunID             string    `json:"run_id"`
	RunNumber         string    `json:"run_number"`
	RunnerArch        string    `json:"runner_arch"`
	RunnerOS          string    `json:"runner_os"`
	ServerURL         string    `json:"server_url"`
	SHA               string    `json:"sha"`
	TriggeringActor   string    `json:"triggering_actor"`
	Workflow          string    `json:"workflow"`
	WorkflowRef       string    `json:"workflow_ref"`
	WorkflowSHA       string    `json:"workflow_sha"`
	Workspace         string    `json:"workspace"`
	CreatedAt         time.Time `json:"created_at"`
	UpdateAt          time.Time `json:"updated_at"`
}

func (s ScenarioGitHub) Type() string {
	return "github"
}

func (s ScenarioGitHub) Clone() Scenario {
	return ScenarioGitHub{
		ID:                s.ID,
		Action:            s.Action,
		Actor:             s.Actor,
		ActorID:           s.ActorID,
		EventName:         s.EventName,
		Job:               s.Job,
		Ref:               s.Ref,
		RefName:           s.RefName,
		RefProtected:      s.RefProtected,
		RefType:           s.RefType,
		Repository:        s.Repository,
		RepositoryID:      s.RepositoryID,
		RepositoryOwner:   s.RepositoryOwner,
		RepositoryOwnerID: s.RepositoryOwnerID,
		RunAttempt:        s.RunAttempt,
		RunID:             s.RunID,
		RunNumber:         s.RunNumber,
		RunnerArch:        s.RunnerArch,
		RunnerOS:          s.RunnerOS,
		ServerURL:         s.ServerURL,
		SHA:               s.SHA,
		TriggeringActor:   s.TriggeringActor,
		Workflow:          s.Workflow,
		WorkflowRef:       s.WorkflowRef,
		WorkflowSHA:       s.WorkflowSHA,
		Workspace:         s.Workspace,
		CreatedAt:         s.CreatedAt,
		UpdateAt:          s.UpdateAt,
	}
}

func (s ScenarioGitHub) IsZero() bool {
	return s.ID == "" && s.Action == "" && s.Actor == "" && s.Repository == ""
}

func (s ScenarioGitHub) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return []byte("null"), nil
	}

	m := make(map[string]string)

	// Always included fields.

	m["id"] = s.ID
	m["action"] = s.Action
	m["actor"] = s.Actor
	m["actor_id"] = s.ActorID
	m["event_name"] = s.EventName
	m["job"] = s.Job

	m["ref"] = s.Ref
	m["ref_name"] = s.RefName
	m["ref_protected"] = strconv.FormatBool(s.RefProtected)
	m["ref_type"] = s.RefType

	m["repository"] = s.Repository
	m["repository_id"] = s.RepositoryID
	m["repository_owner"] = s.RepositoryOwner
	m["repository_owner_id"] = s.RepositoryOwnerID

	m["run_attempt"] = s.RunAttempt
	m["run_id"] = s.RunID
	m["run_number"] = s.RunNumber

	m["runner_arch"] = s.RunnerArch
	m["runner_os"] = s.RunnerOS
	m["server_url"] = s.ServerURL

	m["sha"] = s.SHA
	m["triggering_actor"] = s.TriggeringActor

	m["workflow"] = s.Workflow
	m["workflow_ref"] = s.WorkflowRef
	m["workflow_sha"] = s.WorkflowSHA

	m["workspace"] = s.Workspace

	m["created_at"] = s.CreatedAt.Format(time.RFC3339)
	m["updated_at"] = s.UpdateAt.Format(time.RFC3339)

	return json.Marshal(m)
}

// Scenario HostOS.

type ScenarioHostOS struct {
	MachineID string `json:"machine_id"`
	Hostname  string `json:"hostname"`
	IP        string `json:"ip"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func (s ScenarioHostOS) Type() string {
	return "hostos"
}

func (s ScenarioHostOS) Clone() Scenario {
	return ScenarioHostOS{
		MachineID: s.MachineID,
		Hostname:  s.Hostname,
		IP:        s.IP,
		OS:        s.OS,
		Arch:      s.Arch,
	}
}

func (s ScenarioHostOS) IsZero() bool {
	return s.Hostname == "" && s.IP == "" && s.MachineID == "" && s.OS == "" && s.Arch == ""
}

func (s ScenarioHostOS) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return []byte("null"), nil
	}

	m := make(map[string]string)

	// Always included fields.
	m["machine_id"] = s.MachineID
	m["hostname"] = s.Hostname

	// Omit empty fields.
	if s.IP != "" {
		m["ip"] = s.IP
	}
	if s.OS != "" {
		m["os"] = s.OS
	}
	if s.Arch != "" {
		m["arch"] = s.Arch
	}

	return json.Marshal(m)
}

// Scenario K8S.

type ScenarioK8S struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Node      string `json:"node"`
}

func (s ScenarioK8S) Type() string {
	return "k8s"
}

func (s ScenarioK8S) Clone() Scenario {
	return ScenarioK8S{
		Cluster:   s.Cluster,
		Namespace: s.Namespace,
		Pod:       s.Pod,
		Node:      s.Node,
	}
}

func (s ScenarioK8S) IsZero() bool {
	return s.Cluster == "" && s.Namespace == "" && s.Pod == "" && s.Node == ""
}

func (s ScenarioK8S) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return []byte("null"), nil
	}

	m := make(map[string]string)

	// Always included fields.
	m["cluster"] = s.Cluster
	m["namespace"] = s.Namespace
	m["pod"] = s.Pod
	m["node"] = s.Node

	return json.Marshal(m)
}
