package ongoing

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/google/go-cmp/cmp"
)

func TestScore_Clone(t *testing.T) {
	orig := Score{
		Source:        "s",
		Severity:      50,
		SeverityLevel: "medium",
		Confidence:    0.8,
		RiskScore:     40,
		Reasons:       []string{"reason_score_one_abc", "reason_score_two_xyz"},
	}
	c := orig.Clone()
	assert.Equal(t, orig, c)
	c.Severity = 100
	assert.Equal(t, 50, orig.Severity)
}

func TestScore_IsZero(t *testing.T) {
	assert.True(t, Score{}.IsZero())
	assert.True(t, Score{RiskScore: 0}.IsZero())
	assert.False(t, Score{Source: "garnet"}.IsZero())
	assert.False(t, Score{Severity: 50}.IsZero())
	assert.False(t, Score{SeverityLevel: "none"}.IsZero())
	assert.False(t, Score{Confidence: 0.1}.IsZero())
	assert.False(t, Score{RiskScore: 10}.IsZero())
	assert.False(t, Score{Reasons: []string{"reason"}}.IsZero())
}

func TestScore_MarshalJSON(t *testing.T) {
	b, err := json.Marshal(Score{})
	assert.NoError(t, err)
	assert.Equal(t, "null", string(b))

	b, err = json.Marshal(Score{RiskScore: 0})
	assert.NoError(t, err)
	assert.Equal(t, "null", string(b))

	s := Score{
		Source:        "g",
		Severity:      75,
		SeverityLevel: "high",
		Confidence:    0.85,
		RiskScore:     50,
	}

	b, err = json.Marshal(s)
	assert.NoError(t, err)
	assert.Contains(t, string(b), `"risk_score":50`)

	s2 := Score{
		Source:        "g",
		Severity:      0,
		SeverityLevel: "none",
		Confidence:    0.5,
	}

	b, err = json.Marshal(s2)
	assert.NoError(t, err)
	assert.NotContains(t, string(b), "risk_score")
}

func TestProfile(t *testing.T) {
	want := Profile{
		Base: Base{
			UUID:      "det-001",
			Timestamp: time.Date(2026, 2, 12, 10, 15, 0, 0, time.UTC),
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
				Reasons: []string{
					"domain_not_seen_before",
					"process_contacted_external_service",
				},
			},
			Background: Background{
				Files: []File{
					{
						UUID: "file-001",
						Path: "/srv/app/bin/worker",
						Dir:  "/srv/app/bin",
						Base: "worker",
						Type: "regular",
						Owner: FileOwner{
							UID: 1000,
							GID: 1000,
						},
						Actions: FileActions{
							Actions: []string{"read", "exec"},
							Read:    true,
							Exec:    true,
						},
						Permissions: FilePermissions{
							Mode:       "0755",
							OwnerRead:  true,
							OwnerWrite: true,
							OwnerExec:  true,
							GroupRead:  true,
							GroupExec:  true,
							OtherRead:  true,
							OtherExec:  true,
						},
						Metadata: FileMetadata{
							Size:     1048576,
							Access:   time.Date(2026, 2, 12, 10, 14, 40, 0, time.UTC),
							Change:   time.Date(2026, 2, 12, 10, 14, 30, 0, time.UTC),
							Creation: time.Date(2026, 2, 1, 8, 0, 0, 0, time.UTC),
						},
					},
					{
						UUID: "file-002",
						Path: "/srv/app/config.yaml",
						Dir:  "/srv/app",
						Base: "config.yaml",
						Type: "regular",
						Owner: FileOwner{
							UID: 1000,
							GID: 1000,
						},
						Actions: FileActions{
							Actions: []string{"open", "read"},
							Open:    true,
							Read:    true,
						},
						Permissions: FilePermissions{
							Mode:       "0644",
							OwnerRead:  true,
							OwnerWrite: true,
							GroupRead:  true,
							OtherRead:  true,
						},
						Metadata: FileMetadata{
							Size:     2048,
							Access:   time.Date(2026, 2, 12, 10, 14, 0, 0, time.UTC),
							Change:   time.Date(2026, 2, 10, 12, 0, 0, 0, time.UTC),
							Creation: time.Date(2026, 1, 20, 9, 0, 0, 0, time.UTC),
						},
					},
				},
				Flows: []Flow{
					{
						UUID:      "flow-001",
						IPVersion: 4,
						Proto:     "tcp",
						Local: Node{
							Address: "10.0.0.5",
							Name:    "build-agent",
							Names:   []string{"build-agent.local"},
							Port:    50432,
						},
						Remote: Node{
							Address: "93.184.216.34",
							Name:    "example.com",
							Names:   []string{"example.com", "www.example.com"},
							Port:    443,
						},
						ServicePort: 443,
						Flags: Flags{
							Egress:  true,
							Started: true,
							Ended:   true,
						},
						Phase: Phase{
							Direction:  "egress",
							InitatedBy: "local",
							Status:     "completed",
							EndedBy:    "remote",
						},
					},
					{
						UUID:      "flow-002",
						IPVersion: 4,
						Proto:     "icmp",
						ICMP: ICMP{
							Type: "8",
							Code: "0",
						},
						Local: Node{
							Address: "10.0.0.5",
							Port:    0,
						},
						Remote: Node{
							Address: "10.0.0.10",
							Port:    0,
						},
						Flags: Flags{
							Egress:  true,
							Started: true,
						},
						Phase: Phase{
							Direction:  "egress",
							InitatedBy: "local",
							Status:     "ongoing",
							EndedBy:    "",
						},
					},
				},
				Containers: Containers{
					MntNamespaceIDs: []ContainerID{{Name: "mnt-namespace", ID: "mnt-123"}},
					PidNamespaceIDs: []ContainerID{{Name: "pid-namespace", ID: "pid-123"}},
					UtsNamespaceIDs: []ContainerID{{Name: "uts-namespace", ID: "uts-123"}},
					IpcNamespaceIDs: []ContainerID{{Name: "ipc-namespace", ID: "ipc-123"}},
					NetNamespaceIDs: []ContainerID{{Name: "net-namespace", ID: "net-123"}},
					CgroupNamespaceIDs: []ContainerID{{
						Name: "cgroup-namespace",
						ID:   "cgroup-123",
					}},
					Containers: []Container{
						{
							ID:           "container-abc123",
							Name:         "build-runner",
							HostName:     "runner-host",
							ImageID:      "sha256:deadbeef",
							Image:        "ghcr.io/org/runner",
							Version:      "1.2.3",
							Runtime:      "containerd",
							Driver:       "overlay2",
							PID:          4242,
							ExitCode:     137,
							Status:       "running",
							IsAttached:   true,
							Path:         "/usr/bin/runner",
							Cwd:          "/workdir",
							CreatedAt:    time.Date(2026, 2, 12, 9, 0, 0, 0, time.UTC),
							StartedAt:    time.Date(2026, 2, 12, 9, 1, 0, 0, time.UTC),
							FinishedAt:   time.Date(2026, 2, 12, 11, 0, 0, 0, time.UTC),
							Mounts:       []Mount{{Source: "/var/lib/runner", Destination: "/workdir", Type: "bind"}},
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
						Start:      time.Date(2026, 2, 12, 9, 1, 0, 0, time.UTC),
						Exit:       time.Date(2026, 2, 12, 10, 15, 10, 0, time.UTC),
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
						Start:   time.Date(2026, 2, 12, 8, 55, 0, 0, time.UTC),
						Exit:    time.Date(2026, 2, 12, 10, 20, 0, 0, time.UTC),
						Code:    0,
						UID:     0,
						Pid:     120,
						Ppid:    1,
						Comm:    "containerd",
						Cmd:     "/usr/bin/containerd",
						Exe:     "/usr/bin/containerd",
						Args:    "--config /etc/containerd/config.toml",
						Envs:    "PATH=/usr/bin",
						Loader:  "/lib64/ld-linux-x86-64.so.2",
						PrevExe: "/sbin/init",
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
			Egress: Direction{
				Peers: []Peer{
					{
						Result:        ResultBad,
						Protocol:      "tcp",
						LocalAddress:  "10.0.0.5",
						RemoteAddress: "93.184.216.34",
						LocalNames:    []string{"build-agent", "build-agent.local"},
						RemoteNames:   []string{"example.com", "www.example.com"},
						RemotePorts:   []string{"443", "8443"},
						Detections:    []string{"det-001", "det-005"},
						ProcTrees: []ProcessTree{
							{
								Process:  "/usr/bin/runner --once",
								Ancestry: []string{"/usr/bin/bash -lc ./start.sh", "/sbin/init"},
							},
						},
						RemoteGeoInfo: GeoIPLocation{
							Latitude:      37.7749,
							Longitude:     -122.4194,
							Continent:     "North America",
							ContinentCode: "NA",
							Country:       "United States",
							CountryCode:   "US",
							Region:        "CA",
							RegionName:    "California",
							City:          "San Francisco",
							ISP:           "Example ISP",
							Org:           "Example Org",
							Asname:        "AS15133",
						},
					},
				},
				Domains: []string{"example.com", "registry.npmjs.org"},
			},
			Ingress: Direction{
				Peers: []Peer{
					{
						Result:        ResultAttention,
						Protocol:      "udp",
						LocalAddress:  "10.0.0.5",
						RemoteAddress: "10.0.0.10",
						LocalNames:    []string{"runner-host"},
						RemoteNames:   []string{"metrics.local"},
						RemotePorts:   []string{"53"},
						Detections:    []string{"det-002"},
						ProcTrees: []ProcessTree{
							{
								Process:  "/usr/bin/resolvectl query metrics.local",
								Ancestry: []string{"/usr/bin/systemd-resolved"},
							},
						},
						RemoteGeoInfo: GeoIPLocation{
							Latitude:      40.7128,
							Longitude:     -74.0060,
							Continent:     "North America",
							ContinentCode: "NA",
							Country:       "United States",
							CountryCode:   "US",
							Region:        "NY",
							RegionName:    "New York",
							City:          "New York",
							ISP:           "Datacenter ISP",
							Org:           "Metrics Org",
							Asname:        "AS64500",
						},
					},
				},
				Domains: []string{"metrics.local"},
			},
			Local: Direction{
				Peers: []Peer{
					{
						Result:        ResultGood,
						Protocol:      "unix",
						LocalAddress:  "/var/run/runner.sock",
						RemoteAddress: "/var/run/docker.sock",
						LocalNames:    []string{"runner"},
						RemoteNames:   []string{"docker"},
						RemotePorts:   []string{"0"},
						Detections:    []string{"det-003"},
						ProcTrees: []ProcessTree{
							{
								Process:  "/usr/bin/runner --once",
								Ancestry: []string{"/usr/bin/containerd"},
							},
						},
						RemoteGeoInfo: GeoIPLocation{
							Continent:     "local",
							ContinentCode: "LC",
							Country:       "local",
							CountryCode:   "LC",
							Region:        "local",
							RegionName:    "local",
							City:          "local",
							ISP:           "local",
							Org:           "local",
							Asname:        "local",
						},
					},
				},
				Domains: []string{"localhost", "docker.internal"},
			},
		},
		Assertions: []Assertion{
			{
				Result:   ResultBad,
				ResultID: ResultNoBadEgressDomain,
				Evidence: []Evidence{
					{
						Timestamp: time.Date(2026, 2, 12, 10, 14, 58, 0, time.UTC),
						EventName: "network_connection",
						Peer: Peer{
							Result:        ResultBad,
							Protocol:      "tcp",
							LocalAddress:  "10.0.0.5",
							RemoteAddress: "93.184.216.34",
							LocalNames:    []string{"build-agent.local"},
							RemoteNames:   []string{"example.com"},
							RemotePorts:   []string{"443"},
							Detections:    []string{"det-001"},
							ProcTrees: []ProcessTree{
								{
									Process:  "/usr/bin/runner --once",
									Ancestry: []string{"/usr/bin/bash -lc ./start.sh"},
								},
							},
							RemoteGeoInfo: GeoIPLocation{
								Latitude:      37.7749,
								Longitude:     -122.4194,
								Continent:     "North America",
								ContinentCode: "NA",
								Country:       "United States",
								CountryCode:   "US",
								Region:        "CA",
								RegionName:    "California",
								City:          "San Francisco",
								ISP:           "Example ISP",
								Org:           "Example Org",
								Asname:        "AS15133",
							},
						},
					},
				},
			},
		},
		Telemetry: Telemetry{
			Network: NetTelemetry{
				Egress:  DirectionNetTelemetry{TotalDomains: 5, TotalConnections: 20},
				Ingress: DirectionNetTelemetry{TotalDomains: 8, TotalConnections: 10},
				Local:   DirectionNetTelemetry{TotalDomains: 3, TotalConnections: 15},
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
