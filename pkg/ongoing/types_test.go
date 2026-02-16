package ongoing

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/google/go-cmp/cmp"
)

func TestProfile(t *testing.T) {
	want := Profile{
		Base: Base{
			UUID:      "det-001",
			Timestamp: "2026-02-12T10:15:00Z",
			Note:      "Outbound connection to new domain",
			Metadata: Metadata{
				Kind:          "profile",
				Name:          "egress-profile",
				Format:        "json",
				Version:       "1.0",
				Description:   "Profile for outbound traffic",
				Tactic:        "command-and-control",
				Technique:     "T1071",
				SubTechnique:  "T1071.001",
				Importance:    "high",
				Documentation: "https://example.com/docs/egress-profile",
			},
			Attenuator: Attenuator{
				AttenuatedBy:     "garnet-attenuator",
				Interpretation:   "Known update service",
				Thinking:         "Domain matches allowlist",
				IsFalsePositive:  false,
				NewSeverity:      40,
				NewSeverityLevel: "medium",
				NewConfidence:    0.65,
				NewRiskScore:     35.2,
			},
			Score: Score{
				Source:        "rule:egress-profile",
				Severity:      72,
				SeverityLevel: "high",
				Confidence:    0.84,
				RiskScore:     60.3,
			},
			Background: Background{
				Files: FileAggregate{
					Root: FSDir{
						Path: "/srv/app",
						Base: "app",
						Dirs: []FSDir{
							{
								Path: "/srv/app/bin",
								Base: "bin",
								Files: []FSFile{
									{
										Path:    "/srv/app/bin/worker",
										Base:    "worker",
										Actions: []string{"read", "exec"},
										Mode:    "0755",
										Owner:   FileOwner{UID: 1000, GID: 1000},
										Metadata: FileMetadata{
											Size:     1048576,
											Access:   "2026-02-12T10:14:40Z",
											Change:   "2026-02-12T10:14:30Z",
											Creation: "2026-02-01T08:00:00Z",
										},
									},
								},
							},
						},
						Files: []FSFile{
							{
								Path:    "/srv/app/config.yaml",
								Base:    "config.yaml",
								Actions: []string{"open", "read"},
								Mode:    "0644",
								Owner:   FileOwner{UID: 1000, GID: 1000},
								Metadata: FileMetadata{
									Size:     2048,
									Access:   "2026-02-12T10:14:00Z",
									Change:   "2026-02-10T12:00:00Z",
									Creation: "2026-01-20T09:00:00Z",
								},
							},
						},
					},
				},
				Flows: FlowAggregate{
					IPVersion: 4,
					Protocols: []ProtocolAggregate{
						{
							Proto: "tcp",
							Pairs: []ProtocolLocalRemoteAgg{
								{
									Nodes: LocalRemotePair{
										Local: ProtocolNode{
											Address: "10.0.0.5",
											Name:    "build-agent",
											Names:   []string{"build-agent.local"},
										},
										Remote: ProtocolNode{
											Address: "93.184.216.34",
											Name:    "example.com",
											Names:   []string{"example.com", "www.example.com"},
										},
									},
									PortMatrix: []PortCommAgg{
										{
											SrcPort: 50432,
											DstPort: 443,
											Phase: Phase{
												Direction:  "egress",
												InitatedBy: "local",
												Status:     "completed",
												EndedBy:    "remote",
											},
										},
										{
											SrcPort: 50433,
											DstPort: 80,
											Phase: Phase{
												Direction:  "egress",
												InitatedBy: "local",
												Status:     "terminated",
												EndedBy:    "local",
											},
										},
									},
								},
							},
						},
						{
							Proto: "icmp",
							ICMPs: []ICMP{
								{Type: "8", Code: "0"},
							},
						},
					},
				},
				Containers: ContainerAggregate{
					MntNamespaceIDs: []ContainerPair{
						{Name: "mnt-namespace", ID: "mnt-123"},
					},
					PidNamespaceIDs: []ContainerPair{
						{Name: "pid-namespace", ID: "pid-123"},
					},
					UtsNamespaceIDs: []ContainerPair{
						{Name: "uts-namespace", ID: "uts-123"},
					},
					IpcNamespaceIDs: []ContainerPair{
						{Name: "ipc-namespace", ID: "ipc-123"},
					},
					NetNamespaceIDs: []ContainerPair{
						{Name: "net-namespace", ID: "net-123"},
					},
					CgroupNamespaceIDs: []ContainerPair{
						{Name: "cgroup-namespace", ID: "cgroup-123"},
					},
					Containers: []Container{
						{
							ID:         "container-abc123",
							Name:       "build-runner",
							HostName:   "runner-host",
							ImageID:    "sha256:deadbeef",
							Image:      "ghcr.io/org/runner",
							Version:    "1.2.3",
							Runtime:    "containerd",
							Driver:     "overlay2",
							PID:        4242,
							ExitCode:   0,
							Status:     "running",
							IsAttached: true,
							Path:       "/usr/bin/runner",
							Cwd:        "/workdir",
							CreatedAt:  "2026-02-12T09:00:00Z",
							StartedAt:  "2026-02-12T09:01:00Z",
							FinishedAt: "2026-02-12T11:00:00Z",
							Mounts: []Mount{
								{Source: "/var/lib/runner", Destination: "/workdir", Type: "bind"},
								{Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock", Type: "bind"},
							},
							NetworkMode:  "bridge",
							CgroupnsMode: "private",
							IpcMode:      "private",
							PidMode:      "host",
							UsernsMode:   "private",
							UTSMode:      "private",
							Env:          []string{"ENV=prod", "LOG_LEVEL=info"},
							Cmd:          []string{"/usr/bin/runner", "--once"},
							Namespaces: Namespaces{
								MNTNs:    4026531840,
								PIDNs:    4026531836,
								UTSNs:    4026531838,
								IPCNs:    4026531839,
								NetNs:    4026531993,
								CgroupNs: 4026531835,
							},
						},
					},
				},
				Ancestry: []Process{
					{
						Start:      "2026-02-12T09:01:00Z",
						Exit:       "2026-02-12T10:15:10Z",
						Code:       0,
						UID:        1000,
						Pid:        4321,
						Ppid:       4210,
						Comm:       "runner",
						Cmd:        "/usr/bin/runner --once",
						Exe:        "/usr/bin/runner",
						Args:       "--once",
						Envs:       "ENV=prod LOG_LEVEL=info",
						Loader:     "/lib64/ld-linux-x86-64.so.2",
						PrevExe:    "/usr/bin/bash",
						PrevArgs:   "-lc ./start.sh",
						PrevEnvs:   "PATH=/usr/bin",
						PrevLoader: "/lib64/ld-linux-x86-64.so.2",
						Namespaces: Namespaces{
							MNTNs:    4026531840,
							PIDNs:    4026531836,
							UTSNs:    4026531838,
							IPCNs:    4026531839,
							NetNs:    4026531993,
							CgroupNs: 4026531835,
						},
					},
					{
						Start:      "2026-02-12T08:55:00Z",
						Exit:       "2026-02-12T10:20:00Z",
						Code:       0,
						UID:        0,
						Pid:        120,
						Ppid:       1,
						Comm:       "containerd",
						Cmd:        "/usr/bin/containerd",
						Exe:        "/usr/bin/containerd",
						Args:       "--config /etc/containerd/config.toml",
						Envs:       "PATH=/usr/bin",
						Loader:     "/lib64/ld-linux-x86-64.so.2",
						PrevExe:    "/sbin/init",
						PrevArgs:   "",
						PrevEnvs:   "",
						PrevLoader: "",
						Namespaces: Namespaces{
							MNTNs:    4026531840,
							PIDNs:    4026531836,
							UTSNs:    4026531838,
							IPCNs:    4026531839,
							NetNs:    4026531993,
							CgroupNs: 4026531835,
						},
					},
				},
			},
			Scenarios: Scenarios{
				GitHub: ScenarioGitHub{
					ScenarioType:      ScenarioTypeGitHub,
					ID:                "evt-123",
					Action:            "completed",
					Actor:             "octocat",
					ActorID:           "1001",
					EventName:         "workflow_run",
					Job:               "build",
					Ref:               "refs/heads/main",
					RefName:           "main",
					RefProtected:      "true",
					RefType:           "branch",
					Repository:        "garnet-org/jibril-ashkaal",
					RepositoryID:      "2002",
					RepositoryOwner:   "garnet-org",
					RepositoryOwnerID: "3003",
					RunAttempt:        "1",
					RunID:             "run-456",
					RunNumber:         "88",
					RunnerArch:        "x64",
					RunnerOS:          "linux",
					ServerURL:         "https://github.com",
					SHA:               "abcdef1234567890",
					TriggeringActor:   "octocat",
					Workflow:          "build.yml",
					WorkflowRef:       "refs/heads/main",
					WorkflowSHA:       "123456abcdef",
					Workspace:         "/home/runner/work/jibril-ashkaal",
					CreatedAt:         time.Date(2026, 2, 12, 9, 30, 0, 0, time.UTC),
					UpdateAt:          time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC),
				},
				HostOS: ScenarioHostOS{
					ScenarioType: ScenarioTypeHostOS,
					MachineID:    "machine-001",
					Hostname:     "runner-host",
					IP:           "10.0.0.5",
					OS:           "linux",
					Arch:         "amd64",
				},
				K8S: ScenarioK8S{
					ScenarioType: ScenarioTypeK8S,
					Cluster:      "prod-cluster",
					Namespace:    "ci",
					Pod:          "runner-0",
					Node:         "node-a",
				},
			},
		},
		Network: NetProfile{
			Egress: Egress{
				Peers: []Peer{
					{
						Protocol:      "tcp",
						LocalAddress:  "10.0.0.5",
						LocalName:     "build-agent",
						LocalNames:    []string{"build-agent.local"},
						RemoteAddress: "93.184.216.34",
						RemoteName:    "example.com",
						RemoteNames:   []string{"example.com", "www.example.com"},
						UsedPorts: []PortCommAgg{
							{
								SrcPort: 50432,
								DstPort: 443,
								Phase: Phase{
									Direction:  "egress",
									InitatedBy: "local",
									Status:     "completed",
									EndedBy:    "remote",
								},
							},
						},
						Status:   "allowed",
						Reason:   "policy-allowlist",
						Process:  "/usr/bin/runner",
						Ancestry: []string{"/usr/bin/containerd", "/usr/bin/runner"},
					},
				},
				SeenDomains: []string{"example.com", "registry.npmjs.org"},
			},
		},
		Assertions: []Assertion{
			{
				ID:        "assert-1",
				EventKind: "network",
				Result:    "suspicious",
				Details:   "New outbound domain observed during build",
				Evidence: []Evidence{
					{
						Timestamp:   "2026-02-12T10:14:45Z",
						EventKind:   "egress",
						Domain:      "example.com",
						PeerName:    "example.com",
						PeerAddress: "93.184.216.34",
						Process:     "/usr/bin/runner",
						Ancestry:    []string{"/usr/bin/containerd", "/usr/bin/runner"},
					},
					{
						Timestamp:   "2026-02-12T10:14:46Z",
						EventKind:   "dns",
						Domain:      "example.com",
						PeerName:    "dns-resolver",
						PeerAddress: "10.0.0.2",
						Process:     "/usr/bin/runner",
						Ancestry:    []string{"/usr/bin/containerd", "/usr/bin/runner"},
					},
				},
			},
		},
		Telemetry: Telemetry{
			NetTelemetry: NetTelemetry{
				EgressTotalDomains:     12,
				EgressTotalConnections: 42,
			},
		},
	}

	b, err := json.Marshal(want)
	assert.NoError(t, err)

	var got Profile
	err = json.Unmarshal(b, &got)
	assert.NoError(t, err)

	diff := cmp.Diff(want, got)
	if diff != "" {
		t.Errorf("Profile mismatch (-want +got):\n%s", diff)
	}
}
