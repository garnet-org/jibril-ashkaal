package ongoing

import (
	"encoding/json"
	"time"
)

type ScenarioTypeName string

const (
	ScenarioTypeGitHub ScenarioTypeName = "github"
	ScenarioTypeHostOS ScenarioTypeName = "hostos"
	ScenarioTypeK8S    ScenarioTypeName = "k8s"
)

func (s ScenarioTypeName) Num() int {
	switch s {
	case ScenarioTypeGitHub:
		return 1
	case ScenarioTypeHostOS:
		return 2
	case ScenarioTypeK8S:
		return 3
	}
	return 0
}

type Scenarios struct {
	GitHub ScenarioGitHub `json:"github,omitzero" desc:"GitHub Actions workflow scenario metadata."`
	HostOS ScenarioHostOS `json:"hostos,omitzero" desc:"Host operating system scenario metadata."`
	K8S    ScenarioK8S    `json:"k8s,omitzero" desc:"Kubernetes pod and cluster scenario metadata."`
}

func (s Scenarios) Clone() Scenarios {
	return Scenarios{
		GitHub: s.GitHub.Clone().(ScenarioGitHub),
		HostOS: s.HostOS.Clone().(ScenarioHostOS),
		K8S:    s.K8S.Clone().(ScenarioK8S),
	}
}

func (s Scenarios) IsZero() bool {
	return s.GitHub.IsZero() &&
		s.HostOS.IsZero() &&
		s.K8S.IsZero()
}

func (s Scenarios) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return []byte("null"), nil
	}

	created := struct {
		GitHub *ScenarioGitHub `json:"github,omitempty"`
		HostOS *ScenarioHostOS `json:"hostos,omitempty"`
		K8S    *ScenarioK8S    `json:"k8s,omitempty"`
	}{}

	if !s.GitHub.IsZero() {
		created.GitHub = &s.GitHub
	}
	if !s.HostOS.IsZero() {
		created.HostOS = &s.HostOS
	}
	if !s.K8S.IsZero() {
		created.K8S = &s.K8S
	}

	return json.Marshal(created)
}

func (s Scenarios) MarshalJSONMap() (map[string]any, error) {
	if s.IsZero() {
		return nil, nil
	}
	m := make(map[string]any)

	// Omit empty fields.
	if !s.GitHub.IsZero() {
		githubMap, err := s.GitHub.MarshalJSONMap()
		if err != nil {
			return nil, err
		}
		m["github"] = githubMap
	}
	if !s.HostOS.IsZero() {
		hostosMap, err := s.HostOS.MarshalJSONMap()
		if err != nil {
			return nil, err
		}
		m["hostos"] = hostosMap
	}
	if !s.K8S.IsZero() {
		k8sMap, err := s.K8S.MarshalJSONMap()
		if err != nil {
			return nil, err
		}
		m["k8s"] = k8sMap
	}

	return m, nil
}

// ScenarioType is the interface for all scenario types.

type ScenarioType interface {
	Type() string
	Clone() ScenarioType
	IsZero() bool
}

// Scenario GitHub.

type ScenarioGitHub struct {
	ScenarioType      ScenarioTypeName `json:"scenario_type" desc:"Scenario type identifier (github)."`
	ID                string           `json:"id" desc:"GitHub scenario identifier."`
	Action            string           `json:"action" desc:"Name of the currently running action or step."`
	Actor             string           `json:"actor" desc:"GitHub username that initiated the workflow."`
	ActorID           string           `json:"actor_id" desc:"GitHub account ID of the actor."`
	EventName         string           `json:"event_name" desc:"Webhook event name that triggered the workflow."`
	Job               string           `json:"job" desc:"Job identifier within the workflow."`
	JobIndex          *uint32          `json:"job_index,omitempty" desc:"Zero-based matrix job index."`
	Ref               string           `json:"ref" desc:"Full Git ref that triggered the workflow."`
	RefName           string           `json:"ref_name" desc:"Short branch or tag name of the ref."`
	RefProtected      string           `json:"ref_protected" desc:"Whether the ref is a protected branch."`
	RefType           string           `json:"ref_type" desc:"Type of Git ref (branch or tag)."`
	Repository        string           `json:"repository" desc:"Owner and repository name (owner/repo)."`
	RepositoryID      string           `json:"repository_id" desc:"Unique ID of the GitHub repository."`
	RepositoryOwner   string           `json:"repository_owner" desc:"Repository owner username or organization."`
	RepositoryOwnerID string           `json:"repository_owner_id" desc:"Unique ID of the repository owner."`
	RunAttempt        string           `json:"run_attempt" desc:"Attempt number of the workflow run."`
	RunID             string           `json:"run_id" desc:"Unique ID of the workflow run."`
	RunNumber         string           `json:"run_number" desc:"Run number for the workflow in the repository."`
	RunnerArch        string           `json:"runner_arch" desc:"Architecture of the runner executing the job."`
	RunnerOS          string           `json:"runner_os" desc:"Operating system of the runner executing the job."`
	ServerURL         string           `json:"server_url" desc:"URL of the GitHub server."`
	SHA               string           `json:"sha" desc:"Commit SHA that triggered the workflow."`
	HeadSHA           string           `json:"head_sha,omitempty" desc:"Head commit SHA for pull request workflows."`
	TriggeringActor   string           `json:"triggering_actor" desc:"Username of the user that initiated the workflow run."`
	Workflow          string           `json:"workflow" desc:"Name of the workflow."`
	WorkflowRef       string           `json:"workflow_ref" desc:"Ref path to the workflow file."`
	WorkflowSHA       string           `json:"workflow_sha" desc:"Commit SHA of the workflow file."`
	Workspace         string           `json:"workspace" desc:"Default working directory on the runner."`
	CreatedAt         time.Time        `json:"created_at" desc:"Creation timestamp of the scenario."`
	UpdateAt          time.Time        `json:"updated_at" desc:"Last update timestamp of the scenario."`
}

func (s ScenarioGitHub) Type() string {
	return string(ScenarioTypeGitHub)
}

func (s ScenarioGitHub) Clone() ScenarioType {
	var jobIndex *uint32
	if s.JobIndex != nil {
		v := *s.JobIndex
		jobIndex = &v
	}
	return ScenarioGitHub{
		ScenarioType:      ScenarioTypeGitHub,
		Action:            s.Action,
		ID:                s.ID,
		Actor:             s.Actor,
		ActorID:           s.ActorID,
		EventName:         s.EventName,
		Job:               s.Job,
		JobIndex:          jobIndex,
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
		HeadSHA:           s.HeadSHA,
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
	return s.ID == "" &&
		s.Action == "" &&
		s.Actor == "" &&
		s.ActorID == "" &&
		s.EventName == "" &&
		s.Job == "" &&
		s.JobIndex == nil &&
		s.Ref == "" &&
		s.RefName == "" &&
		s.RefProtected == "" &&
		s.RefType == "" &&
		s.Repository == "" &&
		s.RepositoryID == "" &&
		s.RepositoryOwner == "" &&
		s.RepositoryOwnerID == "" &&
		s.RunAttempt == "" &&
		s.RunID == "" &&
		s.RunNumber == "" &&
		s.RunnerArch == "" &&
		s.RunnerOS == "" &&
		s.ServerURL == "" &&
		s.SHA == "" &&
		s.HeadSHA == "" &&
		s.TriggeringActor == "" &&
		s.Workflow == "" &&
		s.WorkflowRef == "" &&
		s.WorkflowSHA == "" &&
		s.Workspace == "" &&
		s.CreatedAt.IsZero() &&
		s.UpdateAt.IsZero()
}

func (s ScenarioGitHub) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		ScenarioType      ScenarioTypeName `json:"scenario_type"`
		Action            string           `json:"action"`
		ID                string           `json:"id"`
		Actor             string           `json:"actor"`
		ActorID           string           `json:"actor_id"`
		EventName         string           `json:"event_name"`
		Job               string           `json:"job"`
		JobIndex          *uint32          `json:"job_index,omitempty"`
		Ref               string           `json:"ref"`
		RefName           string           `json:"ref_name"`
		RefProtected      string           `json:"ref_protected"`
		RefType           string           `json:"ref_type"`
		Repository        string           `json:"repository"`
		RepositoryID      string           `json:"repository_id"`
		RepositoryOwner   string           `json:"repository_owner"`
		RepositoryOwnerID string           `json:"repository_owner_id"`
		RunAttempt        string           `json:"run_attempt"`
		RunID             string           `json:"run_id"`
		RunNumber         string           `json:"run_number"`
		RunnerArch        string           `json:"runner_arch"`
		RunnerOS          string           `json:"runner_os"`
		ServerURL         string           `json:"server_url"`
		SHA               string           `json:"sha"`
		HeadSHA           string           `json:"head_sha,omitempty"`
		TriggeringActor   string           `json:"triggering_actor"`
		Workflow          string           `json:"workflow"`
		WorkflowRef       string           `json:"workflow_ref"`
		WorkflowSHA       string           `json:"workflow_sha"`
		Workspace         string           `json:"workspace"`
		CreatedAt         time.Time        `json:"created_at"`
		UpdateAt          time.Time        `json:"updated_at"`
	}{
		ScenarioType:      ScenarioTypeGitHub,
		Action:            s.Action,
		ID:                s.ID,
		Actor:             s.Actor,
		ActorID:           s.ActorID,
		EventName:         s.EventName,
		Job:               s.Job,
		JobIndex:          s.JobIndex,
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
		HeadSHA:           s.HeadSHA,
		TriggeringActor:   s.TriggeringActor,
		Workflow:          s.Workflow,
		WorkflowRef:       s.WorkflowRef,
		WorkflowSHA:       s.WorkflowSHA,
		Workspace:         s.Workspace,
		CreatedAt:         s.CreatedAt,
		UpdateAt:          s.UpdateAt,
	})
}

func (s ScenarioGitHub) MarshalJSONMap() (map[string]any, error) {
	if s.IsZero() {
		return nil, nil
	}

	m := make(map[string]any)

	// Always included fields.
	m["scenario_type"] = ScenarioTypeGitHub

	m["action"] = s.Action
	m["id"] = s.ID

	m["actor"] = s.Actor
	m["actor_id"] = s.ActorID

	m["event_name"] = s.EventName
	m["job"] = s.Job
	if s.JobIndex != nil {
		m["job_index"] = *s.JobIndex
	}

	m["ref"] = s.Ref
	m["ref_name"] = s.RefName
	m["ref_protected"] = s.RefProtected
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
	if s.HeadSHA != "" {
		m["head_sha"] = s.HeadSHA
	}
	m["triggering_actor"] = s.TriggeringActor

	m["workflow"] = s.Workflow
	m["workflow_ref"] = s.WorkflowRef
	m["workflow_sha"] = s.WorkflowSHA
	m["workspace"] = s.Workspace

	m["created_at"] = s.CreatedAt
	m["updated_at"] = s.UpdateAt

	return m, nil
}

// Scenario HostOS.

type ScenarioHostOS struct {
	ScenarioType ScenarioTypeName `json:"scenario_type" desc:"Scenario type identifier (hostos)."`
	MachineID    string           `json:"machine_id" desc:"Unique machine identifier of the host."`
	Hostname     string           `json:"hostname" desc:"Hostname of the host."`
	IP           string           `json:"ip" desc:"Primary IP address of the host."`
	OS           string           `json:"os" desc:"Operating system name of the host."`
	Arch         string           `json:"arch" desc:"CPU architecture of the host."`
}

func (s ScenarioHostOS) Type() string {
	return string(ScenarioTypeHostOS)
}

func (s ScenarioHostOS) Clone() ScenarioType {
	return ScenarioHostOS{
		ScenarioType: ScenarioTypeHostOS,
		MachineID:    s.MachineID,
		Hostname:     s.Hostname,
		IP:           s.IP,
		OS:           s.OS,
		Arch:         s.Arch,
	}
}

func (s ScenarioHostOS) IsZero() bool {
	return s.MachineID == "" &&
		s.Hostname == "" &&
		s.IP == "" &&
		s.OS == "" &&
		s.Arch == ""
}

func (s ScenarioHostOS) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		ScenarioType ScenarioTypeName `json:"scenario_type"`
		MachineID    string           `json:"machine_id"`
		Hostname     string           `json:"hostname"`
		IP           string           `json:"ip"`
		OS           string           `json:"os"`
		Arch         string           `json:"arch"`
	}{
		ScenarioType: ScenarioTypeHostOS,
		MachineID:    s.MachineID,
		Hostname:     s.Hostname,
		IP:           s.IP,
		OS:           s.OS,
		Arch:         s.Arch,
	})
}

func (s ScenarioHostOS) MarshalJSONMap() (map[string]any, error) {
	if s.IsZero() {
		return nil, nil
	}

	m := make(map[string]any)

	// Always included fields.
	m["scenario_type"] = string(ScenarioTypeHostOS)
	m["machine_id"] = s.MachineID
	m["hostname"] = s.Hostname
	m["ip"] = s.IP
	m["os"] = s.OS
	m["arch"] = s.Arch

	return m, nil
}

// Scenario K8S.

type ScenarioK8S struct {
	ScenarioType ScenarioTypeName `json:"scenario_type" desc:"Scenario type identifier (k8s)."`
	Cluster      string           `json:"cluster" desc:"Kubernetes cluster name."`
	Namespace    string           `json:"namespace" desc:"Kubernetes namespace of the pod."`
	Pod          string           `json:"pod" desc:"Kubernetes pod name."`
	Node         string           `json:"node" desc:"Kubernetes node name."`
}

func (s ScenarioK8S) Type() string {
	return string(ScenarioTypeK8S)
}

func (s ScenarioK8S) Clone() ScenarioType {
	return ScenarioK8S{
		ScenarioType: ScenarioTypeK8S,
		Cluster:      s.Cluster,
		Namespace:    s.Namespace,
		Pod:          s.Pod,
		Node:         s.Node,
	}
}

func (s ScenarioK8S) IsZero() bool {
	return s.Cluster == "" &&
		s.Namespace == "" &&
		s.Pod == "" &&
		s.Node == ""
}

func (s ScenarioK8S) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(struct {
		ScenarioType ScenarioTypeName `json:"scenario_type"`
		Cluster      string           `json:"cluster"`
		Namespace    string           `json:"namespace"`
		Pod          string           `json:"pod"`
		Node         string           `json:"node"`
	}{
		ScenarioType: ScenarioTypeK8S,
		Cluster:      s.Cluster,
		Namespace:    s.Namespace,
		Pod:          s.Pod,
		Node:         s.Node,
	})
}

func (s ScenarioK8S) MarshalJSONMap() (map[string]any, error) {
	if s.IsZero() {
		return nil, nil
	}

	m := make(map[string]any)

	// Always included fields.
	m["scenario_type"] = ScenarioTypeK8S
	m["cluster"] = s.Cluster
	m["namespace"] = s.Namespace
	m["pod"] = s.Pod
	m["node"] = s.Node

	return m, nil
}
