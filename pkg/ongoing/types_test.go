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

func TestBase_UnmarshalJSON_LegacyTimeLayouts(t *testing.T) {
	testCases := []struct {
		name      string
		timestamp string
		want      time.Time
	}{
		{
			name:      "rfc3339nano",
			timestamp: "2026-02-12T10:15:00.123456789Z",
			want:      time.Date(2026, 2, 12, 10, 15, 0, 123456789, time.UTC),
		},
		{
			name:      "space_nanos",
			timestamp: "2026-02-12 10:15:00.123456789",
			want:      time.Date(2026, 2, 12, 10, 15, 0, 123456789, time.UTC),
		},
		{
			name:      "space_seconds",
			timestamp: "2026-02-12 10:15:00",
			want:      time.Date(2026, 2, 12, 10, 15, 0, 0, time.UTC),
		},
		{
			name:      "t_nanos",
			timestamp: "2026-02-12T10:15:00.123456789",
			want:      time.Date(2026, 2, 12, 10, 15, 0, 123456789, time.UTC),
		},
		{
			name:      "t_seconds",
			timestamp: "2026-02-12T10:15:00",
			want:      time.Date(2026, 2, 12, 10, 15, 0, 0, time.UTC),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(`{"uuid":"det-001","timestamp":"` + tc.timestamp + `"}`)

			var got Base
			err := json.Unmarshal(payload, &got)
			assert.NoError(t, err)
			assert.Equal(t, "det-001", got.UUID)
			assert.Equal(t, tc.want, got.Timestamp)
		})
	}
}

func TestLegacyTime_UnmarshalJSON_Running(t *testing.T) {
	var got legacyTime
	err := got.UnmarshalJSON([]byte(`"running"`))
	assert.NoError(t, err)
	assert.True(t, got.Time.IsZero())
}

func TestProcess_UnmarshalJSON_RunningExit(t *testing.T) {
	payload := []byte(`{"uuid":"proc-001","start":"2026-02-12 10:15:00","exit":"running"}`)

	var got Process
	err := json.Unmarshal(payload, &got)
	assert.NoError(t, err)
	assert.Equal(t, "proc-001", got.UUID)
	assert.Equal(
		t,
		time.Date(2026, 2, 12, 10, 15, 0, 0, time.UTC),
		got.Start,
	)
	assert.True(t, got.Exit.IsZero())
}

func TestEventTypes_UnmarshalJSON_LegacyTimestamp(t *testing.T) {
	payload := []byte(`{"uuid":"det-001","timestamp":"2026-02-12 10:15:00"}`)
	want := time.Date(2026, 2, 12, 10, 15, 0, 0, time.UTC)

	testCases := []struct {
		name   string
		decode func([]byte) (time.Time, error)
	}{
		{
			name: "file_access",
			decode: func(data []byte) (time.Time, error) {
				var got FileAccess
				err := json.Unmarshal(data, &got)
				return got.Timestamp, err
			},
		},
		{
			name: "execution",
			decode: func(data []byte) (time.Time, error) {
				var got Execution
				err := json.Unmarshal(data, &got)
				return got.Timestamp, err
			},
		},
		{
			name: "network_peer",
			decode: func(data []byte) (time.Time, error) {
				var got NetworkPeer
				err := json.Unmarshal(data, &got)
				return got.Timestamp, err
			},
		},
		{
			name: "network_flow",
			decode: func(data []byte) (time.Time, error) {
				var got NetworkFlow
				err := json.Unmarshal(data, &got)
				return got.Timestamp, err
			},
		},
		{
			name: "drop_ip",
			decode: func(data []byte) (time.Time, error) {
				var got DropIP
				err := json.Unmarshal(data, &got)
				return got.Timestamp, err
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.decode(payload)
			assert.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestProfile_UnmarshalJSON_LegacyNestedTimes(t *testing.T) {
	payload := []byte(`{
		"uuid":"profile-001",
		"timestamp":"2026-02-12T10:15:00",
		"background":{
			"ancestry":[{
				"start":"2026-02-12 10:14:00",
				"exit":"2026-02-12T10:14:59.123456789"
			}],
			"file_list":[{
				"metadata":{
					"access":"2026-02-12 10:13:00",
					"change":"2026-02-12T10:12:00",
					"creation":"2026-02-01 08:00:00"
				}
			}],
			"containers":{
				"containers":[{
					"id":"ctr-001",
					"created_at":"2026-02-12 09:00:00",
					"started_at":"2026-02-12T09:01:00",
					"finished_at":"2026-02-12T11:00:00.123456789"
				}]
			}
		},
		"assertions":[{
			"result":"pass",
			"id":"no_bad_egress_domain",
			"evidence":[{
				"timestamp":"2026-02-12 10:11:00",
				"event_name":"evt-001"
			}]
		}]
	}`)

	var got Profile
	err := json.Unmarshal(payload, &got)
	assert.NoError(t, err)

	assert.Equal(
		t,
		time.Date(2026, 2, 12, 10, 15, 0, 0, time.UTC),
		got.Timestamp,
	)
	assert.Equal(t, 1, len(got.Background.Ancestry))
	assert.Equal(
		t,
		time.Date(2026, 2, 12, 10, 14, 0, 0, time.UTC),
		got.Background.Ancestry[0].Start,
	)
	assert.Equal(
		t,
		time.Date(2026, 2, 12, 10, 14, 59, 123456789, time.UTC),
		got.Background.Ancestry[0].Exit,
	)
	assert.Equal(t, 1, len(got.Background.Files))
	assert.Equal(
		t,
		time.Date(2026, 2, 12, 10, 13, 0, 0, time.UTC),
		got.Background.Files[0].Metadata.Access,
	)
	assert.Equal(
		t,
		time.Date(2026, 2, 12, 10, 12, 0, 0, time.UTC),
		got.Background.Files[0].Metadata.Change,
	)
	assert.Equal(
		t,
		time.Date(2026, 2, 1, 8, 0, 0, 0, time.UTC),
		got.Background.Files[0].Metadata.Creation,
	)
	assert.Equal(t, 1, len(got.Background.Containers.Containers))
	assert.Equal(
		t,
		time.Date(2026, 2, 12, 9, 0, 0, 0, time.UTC),
		got.Background.Containers.Containers[0].CreatedAt,
	)
	assert.Equal(
		t,
		time.Date(2026, 2, 12, 9, 1, 0, 0, time.UTC),
		got.Background.Containers.Containers[0].StartedAt,
	)
	assert.Equal(
		t,
		time.Date(2026, 2, 12, 11, 0, 0, 123456789, time.UTC),
		got.Background.Containers.Containers[0].FinishedAt,
	)
	assert.Equal(t, 1, len(got.Assertions))
	assert.Equal(t, 1, len(got.Assertions[0].Evidence))
	assert.Equal(
		t,
		time.Date(2026, 2, 12, 10, 11, 0, 0, time.UTC),
		got.Assertions[0].Evidence[0].Timestamp,
	)
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

func TestBackground_UnmarshalJSON_Compatibility(t *testing.T) {
	newJSON := `{
"file_list":[{"uuid":"file-1","path":"/a","dir":"/","basename":"a","type":"regular","owner":{"uid":0,"gid":0},"actions":{"actions":null},"permissions":{"mode":""},"metadata":{"size":0},"file_hash":0,"dir_hash":0,"base_hash":0}],
"flow_list":[{"uuid":"flow-1","ip_version":4,"proto":"tcp","local":{"addr":"10.0.0.1","port":1},"remote":{"addr":"10.0.0.2","port":2},"service_port":0,"flags":{},"phase":{}}],
"ancestry":[]
}`

	var bg Background
	err := json.Unmarshal([]byte(newJSON), &bg)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(bg.Files))
	assert.Equal(t, 1, len(bg.Flows))
	assert.True(t, bg.LegacyFiles.IsZero())
	assert.True(t, bg.LegacyFlows.IsZero())

	b, err := json.Marshal(bg)
	assert.NoError(t, err)
	assert.Contains(t, string(b), `"file_list"`)
	assert.Contains(t, string(b), `"flow_list"`)
	assert.NotContains(t, string(b), `"files"`)
	assert.NotContains(t, string(b), `"flows"`)

	legacyJSON := `{
"files":{"root":{"path":"/","base":"/","dirs":[],"files":[],"dir_hash":1}},
"flows":{"ip_version":4,"protocols":[],"total_flows":1}
}`

	var legacy Background
	err = json.Unmarshal([]byte(legacyJSON), &legacy)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(legacy.Files))
	assert.Equal(t, 0, len(legacy.Flows))
	assert.False(t, legacy.LegacyFiles.IsZero())
	assert.False(t, legacy.LegacyFlows.IsZero())

	b, err = json.Marshal(legacy)
	assert.NoError(t, err)
	assert.Contains(t, string(b), `"files"`)
	assert.Contains(t, string(b), `"flows"`)
	assert.NotContains(t, string(b), `"file_list"`)
	assert.NotContains(t, string(b), `"flow_list"`)
}
