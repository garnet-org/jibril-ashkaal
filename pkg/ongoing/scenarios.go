package ongoing

import (
	"time"
)

type Scenario interface {
	Type() string
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

func (s ScenarioGitHub) Type() string { return "github" }

// Scenario HostOS.

type ScenarioHostOS struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
}

func (s ScenarioHostOS) Type() string { return "host" }

// Scenario K8S.

type ScenarioK8S struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Node      string `json:"node"`
}

func (s ScenarioK8S) Type() string { return "kubernetes" }
