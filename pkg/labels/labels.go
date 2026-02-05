package labels

import (
	"fmt"

	"github.com/garnet-org/jibril-ashkaal/pkg/kind"
)

//
// Metadata.
//

type Metadata struct {
	Kind          kind.Kind
	Version       float64
	Description   string
	Breed         Breed
	Mechanism     Mechanism
	Tactic        Tactic
	Technique     Technique
	SubTechnique  SubTechnique
	Documentation string
}

//
// Severity Level (none, low, medium, high, critical).
// Tied to Severity.
//

type SeverityLevel string

const (
	SeverityNone     SeverityLevel = "none"
	SeverityLow      SeverityLevel = "low"
	SeverityMedium   SeverityLevel = "medium"
	SeverityHigh     SeverityLevel = "high"
	SeverityCritical SeverityLevel = "critical"
)

func (s SeverityLevel) String() string {
	return string(s)
}

func (s SeverityLevel) Average() int {
	switch s {
	case SeverityNone:
		return 0
	case SeverityLow:
		return 15
	case SeverityMedium:
		return 45
	case SeverityHigh:
		return 75
	case SeverityCritical:
		return 90
	default:
		return 0
	}
}

func (s SeverityLevel) Severity() Severity {
	return Severity(s.Average())
}

//
// Severity (a number from 0 to 100).
// Tied to SeverityLevel.
//

type Severity int

func (p Severity) Level() SeverityLevel {
	if p <= 0 {
		return SeverityNone
	}
	if p <= 29 {
		return SeverityLow
	}
	if p <= 59 {
		return SeverityMedium
	}
	if p <= 79 {
		return SeverityHigh
	}
	return SeverityCritical
}

func (p Severity) String() string {
	return p.Level().String()
}

func (p Severity) Float64() float64 {
	return float64(p)
}

func (p Severity) Int() int {
	return int(p)
}

//
// Confidence (a float from 0.0 to 1.0).
//

type Confidence float64

func (c Confidence) String() string {
	return fmt.Sprintf("%.2f", c)
}

func (c Confidence) Float64() float64 {
	return float64(c)
}

//
// Response.
//

type Response int

const (
	ResponseNone Response = iota
	ResponseIgnore
	ResponseMonitor
	ResponseInvestigate
	ResponseIncident
)

func (r Response) String() string {
	switch r {
	case ResponseNone:
		return "none"
	case ResponseIgnore:
		return "ignore"
	case ResponseMonitor:
		return "monitor"
	case ResponseInvestigate:
		return "investigate"
	case ResponseIncident:
		return "incident"
	default:
		return "none"
	}
}

//
// Breed.
//

type Breed int

const (
	BreedNone Breed = iota
	BreedFileAccess
	BreedRemoteCIDRs
	BreedRemoteDomains
	BreedEnvVars
	BreedEnd
)

func (b Breed) String() string {
	switch b {
	case BreedNone:
		return "none"
	case BreedEnd:
		return "end"
	case BreedFileAccess:
		return "file_access"
	case BreedRemoteCIDRs:
		return "remote_cidrs"
	case BreedRemoteDomains:
		return "remote_domains"
	case BreedEnvVars:
		return "env_vars"
	default:
		return "none"
	}
}

//
// Mechanism.
//

type Mechanism int

const (
	MechNone Mechanism = iota
	MechFileAccess
	MechExecution
	MechFileAccessAndExecution
	MechNetworkPeers
	MechNetworkFlows
	MechEnvVars
	MechEnd
)

func (m Mechanism) String() string {
	switch m {
	case MechNone:
		return "none"
	case MechFileAccess:
		return "file_access"
	case MechExecution:
		return "execution"
	case MechFileAccessAndExecution:
		return "file_access_and_execution"
	case MechNetworkPeers:
		return "network_peers"
	case MechNetworkFlows:
		return "network_flows"
	case MechEnvVars:
		return "env_vars"
	default:
		return "none"
	}
}

//
// Tactic.
//

type TacticInfo struct {
	ID   string // The MITRE ATT&CK tactic code.
	Name string // The name of the tactic.
}

var tacticInfos = []TacticInfo{
	{ID: "TA0000", Name: "None"},
	{ID: "TA0001", Name: "Example"},
	{ID: "TA0001", Name: "Initial Access"},
	{ID: "TA0002", Name: "Execution"},
	{ID: "TA0003", Name: "Persistence"},
	{ID: "TA0004", Name: "Privilege Escalation"},
	{ID: "TA0005", Name: "Defense Evasion"},
	{ID: "TA0006", Name: "Credential Access"},
	{ID: "TA0007", Name: "Discovery"},
	{ID: "TA0008", Name: "Lateral Movement"},
	{ID: "TA0009", Name: "Collection"},
	{ID: "TA0010", Name: "Exfiltration"},
	{ID: "TA0011", Name: "Command and Control"},
	{ID: "TA0040", Name: "Impact"},
	{ID: "TA0042", Name: "Resource Development"},
	{ID: "TA0043", Name: "Reconnaissance"},
	{ID: "TA0000", Name: "End"},
}

type Tactic int

const (
	TacticNone Tactic = iota
	TacticExample
	TacticInitialAccess
	TacticExecution
	TacticPersistence
	TacticPrivilegeEscalation
	TacticDefenseEvasion
	TacticCredentialAccess
	TacticDiscovery
	TacticLateralMovement
	TacticCollection
	TacticExfiltration
	TacticCommandAndControl
	TacticImpact
	TacticResourceDevelopment
	TacticReconnaissance
	TacticEnd
)

func (t Tactic) Label() string {
	if int(t) >= 0 && int(t) < len(tacticInfos) {
		return kind.NormalizeString(tacticInfos[t].Name)
	}
	return kind.NormalizeString(tacticInfos[TacticNone].Name)
}

func (t Tactic) String() string {
	return t.Label()
}

func (t Tactic) Name() string {
	if int(t) >= 0 && int(t) < len(tacticInfos) {
		return tacticInfos[t].Name
	}
	return tacticInfos[TacticNone].Name
}

func (t Tactic) ID() string {
	if int(t) >= 0 && int(t) < len(tacticInfos) {
		return tacticInfos[t].ID
	}
	return tacticInfos[TacticNone].ID
}

//
// Technique.
//

type Technique int

type TechniqueInfo struct {
	Name string
	ID   string
}

const (
	TechniqueNone Technique = iota
	TechniqueExample
	TechniqueValidAccounts
	TechniqueReplicationThroughRemovableMedia
	TechniqueExternalRemoteServices
	TechniqueDriveByCompromise
	TechniqueExploitPublicFacingApplication
	TechniqueSupplyChainCompromise
	TechniqueTrustedRelationship
	TechniqueHardwareAdditions
	TechniquePhishing
	TechniqueWindowsManagementInstrumentation
	TechniqueScheduledTaskJob
	TechniqueCommandAndScriptingInterpreter
	TechniqueSoftwareDeploymentTools
	TechniqueNativeApi
	TechniqueSharedModules
	TechniqueExploitationForClientExecution
	TechniqueUserExecution
	TechniqueInterProcessCommunication
	TechniqueSystemServices
	TechniqueContainerAdministrationCommand
	TechniqueServerlessExecution
	TechniqueCloudAdministrationCommand
	TechniqueBootOrLogonInitializationScripts
	TechniqueAccountManipulation
	TechniqueCreateAccount
	TechniqueOfficeApplicationStartup
	TechniqueBrowserExtensions
	TechniqueBitsJobs
	TechniqueTrafficSignaling
	TechniqueServerSoftwareComponent
	TechniqueImplantInternalImage
	TechniquePreOsBoot
	TechniqueCreateOrModifySystemProcess
	TechniqueEventTriggeredExecution
	TechniqueBootOrLogonAutostartExecution
	TechniqueCompromiseHostSoftwareBinary
	TechniqueModifyAuthenticationProcess
	TechniqueHijackExecutionFlow
	TechniqueProcessInjection
	TechniqueExploitationForPrivilegeEscalation
	TechniqueAccessTokenManipulation
	TechniqueDomainOrTenantPolicyModification
	TechniqueAbuseElevationControlMechanism
	TechniqueEscapeToHost
	TechniqueDirectVolumeAccess
	TechniqueRootkit
	TechniqueObfuscatedFilesOrInformation
	TechniqueMasquerading
	TechniqueIndicatorRemoval
	TechniqueModifyRegistry
	TechniqueDeobfuscateDecodeFilesOrInformation
	TechniqueIndirectCommandExecution
	TechniqueRogueDomainController
	TechniqueExploitationForDefenseEvasion
	TechniqueSystemScriptProxyExecution
	TechniqueSystemBinaryProxyExecution
	TechniqueXslScriptProcessing
	TechniqueTemplateInjection
	TechniqueFileAndDirectoryPermissionsModification
	TechniqueExecutionGuardrails
	TechniqueVirtualizationSandboxEvasion
	TechniqueUseAlternateAuthenticationMaterial
	TechniqueSubvertTrustControls
	TechniqueImpairDefenses
	TechniqueHideArtifacts
	TechniqueModifyCloudComputeInfrastructure
	TechniqueNetworkBoundaryBridging
	TechniqueWeakenEncryption
	TechniqueModifySystemImage
	TechniqueBuildImageOnHost
	TechniqueReflectiveCodeLoading
	TechniqueOsCredentialDumping
	TechniqueNetworkSniffing
	TechniqueInputCapture
	TechniqueBruteForce
	TechniqueMultiFactorAuthenticationInterception
	TechniqueForcedAuthentication
	TechniqueExploitationForCredentialAccess
	TechniqueCloudInstanceMetadataApi
	TechniqueStealApplicationAccessToken
	TechniqueStealWebSessionCookie
	TechniqueUnsecuredCredentials
	TechniqueCredentialsFromPasswordStores
	TechniqueAdversaryInTheMiddle
	TechniqueStealOrForgeKerberosTickets
	TechniqueForgeWebCredentials
	TechniqueMultiFactorAuthenticationRequestGeneration
	TechniqueStealOrForgeAuthenticationCertificates
	TechniqueSystemServiceDiscovery
	TechniqueApplicationWindowDiscovery
	TechniqueQueryRegistry
	TechniqueSystemNetworkConfigurationDiscovery
	TechniqueRemoteSystemDiscovery
	TechniqueSystemOwnerUserDiscovery
	TechniqueNetworkServiceDiscovery
	TechniqueSystemNetworkConnectionsDiscovery
	TechniqueProcessDiscovery
	TechniquePermissionGroupsDiscovery
	TechniqueSystemInformationDiscovery
	TechniqueFileAndDirectoryDiscovery
	TechniqueAccountDiscovery
	TechniquePeripheralDeviceDiscovery
	TechniqueSystemTimeDiscovery
	TechniqueNetworkShareDiscovery
	TechniquePasswordPolicyDiscovery
	TechniqueBrowserInformationDiscovery
	TechniqueDomainTrustDiscovery
	TechniqueSoftwareDiscovery
	TechniqueCloudServiceDiscovery
	TechniqueCloudServiceDashboard
	TechniqueCloudInfrastructureDiscovery
	TechniqueContainerAndResourceDiscovery
	TechniqueSystemLocationDiscovery
	TechniqueGroupPolicyDiscovery
	TechniqueCloudStorageObjectDiscovery
	TechniqueRemoteServices
	TechniqueTaintSharedContent
	TechniqueExploitationOfRemoteServices
	TechniqueInternalSpearphishing
	TechniqueRemoteServiceSessionHijacking
	TechniqueLateralToolTransfer
	TechniqueDataFromLocalSystem
	TechniqueDataFromRemovableMedia
	TechniqueDataFromNetworkSharedDrive
	TechniqueDataStaged
	TechniqueScreenCapture
	TechniqueEmailCollection
	TechniqueClipboardData
	TechniqueAutomatedCollection
	TechniqueAudioCapture
	TechniqueVideoCapture
	TechniqueBrowserSessionHijacking
	TechniqueDataFromInformationRepositories
	TechniqueDataFromCloudStorage
	TechniqueArchiveCollectedData
	TechniqueDataFromConfigurationRepository
	TechniqueExfiltrationOverOtherNetworkMedium
	TechniqueAutomatedExfiltration
	TechniqueScheduledTransfer
	TechniqueDataTransferSizeLimits
	TechniqueExfiltrationOverC2Channel
	TechniqueExfiltrationOverAlternativeProtocol
	TechniqueExfiltrationOverPhysicalMedium
	TechniqueExfiltrationOverWebService
	TechniqueDataObfuscation
	TechniqueFallbackChannels
	TechniqueApplicationLayerProtocol
	TechniqueProxy
	TechniqueCommunicationThroughRemovableMedia
	TechniqueNonApplicationLayerProtocol
	TechniqueWebService
	TechniqueMultiStageChannels
	TechniqueIngressToolTransfer
	TechniqueDataEncoding
	TechniqueRemoteAccessSoftware
	TechniqueDynamicResolution
	TechniqueNonStandardPort
	TechniqueProtocolTunneling
	TechniqueEncryptedChannel
	TechniqueDataDestruction
	TechniqueDataEncryptedForImpact
	TechniqueServiceStop
	TechniqueInhibitSystemRecovery
	TechniqueDefacement
	TechniqueFirmwareCorruption
	TechniqueResourceHijacking
	TechniqueNetworkDenialOfService
	TechniqueEndpointDenialOfService
	TechniqueSystemShutdownReboot
	TechniqueAccountAccessRemoval
	TechniqueDiskWipe
	TechniqueDataManipulation
	TechniqueAcquireInfrastructure
	TechniqueCompromiseInfrastructure
	TechniqueEstablishAccounts
	TechniqueCompromiseAccounts
	TechniqueDevelopCapabilities
	TechniqueObtainCapabilities
	TechniqueStageCapabilities
	TechniqueAcquireAccess
	TechniqueGatherVictimIdentityInformation
	TechniqueGatherVictimNetworkInformation
	TechniqueGatherVictimOrgInformation
	TechniqueGatherVictimHostInformation
	TechniqueSearchOpenWebsitesDomains
	TechniqueSearchVictimOwnedWebsites
	TechniqueActiveScanning
	TechniqueSearchOpenTechnicalDatabases
	TechniqueSearchClosedSources
	TechniquePhishingForInformation
	TechniqueEnd
)

var techniqueInfos = []TechniqueInfo{
	{ID: "T0000", Name: "None"},
	{ID: "T0000", Name: "Example"},
	{ID: "T1078", Name: "Valid Accounts"},
	{ID: "T1091", Name: "Replication Through Removable Media"},
	{ID: "T1133", Name: "External Remote Services"},
	{ID: "T1189", Name: "Drive-by Compromise"},
	{ID: "T1190", Name: "Exploit Public-Facing Application"},
	{ID: "T1195", Name: "Supply Chain Compromise"},
	{ID: "T1199", Name: "Trusted Relationship"},
	{ID: "T1200", Name: "Hardware Additions"},
	{ID: "T1566", Name: "Phishing"},
	{ID: "T1047", Name: "Windows Management Instrumentation"},
	{ID: "T1053", Name: "Scheduled Task/Job"},
	{ID: "T1059", Name: "Command and Scripting Interpreter"},
	{ID: "T1072", Name: "Software Deployment Tools"},
	{ID: "T1106", Name: "Native API"},
	{ID: "T1129", Name: "Shared Modules"},
	{ID: "T1203", Name: "Exploitation for Client Execution"},
	{ID: "T1204", Name: "User Execution"},
	{ID: "T1559", Name: "Inter-Process Communication"},
	{ID: "T1569", Name: "System Services"},
	{ID: "T1609", Name: "Container Administration Command"},
	{ID: "T1648", Name: "Serverless Execution"},
	{ID: "T1651", Name: "Cloud Administration Command"},
	{ID: "T1037", Name: "Boot or Logon Initialization Scripts"},
	{ID: "T1098", Name: "Account Manipulation"},
	{ID: "T1136", Name: "Create Account"},
	{ID: "T1137", Name: "Office Application Startup"},
	{ID: "T1176", Name: "Browser Extensions"},
	{ID: "T1197", Name: "BITS Jobs"},
	{ID: "T1205", Name: "Traffic Signaling"},
	{ID: "T1505", Name: "Server Software Component"},
	{ID: "T1525", Name: "Implant Internal Image"},
	{ID: "T1542", Name: "Pre-OS Boot"},
	{ID: "T1543", Name: "Create or Modify System Process"},
	{ID: "T1546", Name: "Event Triggered Execution"},
	{ID: "T1547", Name: "Boot or Logon Autostart Execution"},
	{ID: "T1554", Name: "Compromise Host Software Binary"},
	{ID: "T1556", Name: "Modify Authentication Process"},
	{ID: "T1574", Name: "Hijack Execution Flow"},
	{ID: "T1055", Name: "Process Injection"},
	{ID: "T1068", Name: "Exploitation for Privilege Escalation"},
	{ID: "T1134", Name: "Access Token Manipulation"},
	{ID: "T1484", Name: "Domain or Tenant Policy Modification"},
	{ID: "T1548", Name: "Abuse Elevation Control Mechanism"},
	{ID: "T1611", Name: "Escape to Host"},
	{ID: "T1006", Name: "Direct Volume Access"},
	{ID: "T1014", Name: "Rootkit"},
	{ID: "T1027", Name: "Obfuscated Files or Information"},
	{ID: "T1036", Name: "Masquerading"},
	{ID: "T1070", Name: "Indicator Removal"},
	{ID: "T1112", Name: "Modify Registry"},
	{ID: "T1140", Name: "Deobfuscate/Decode Files or Information"},
	{ID: "T1202", Name: "Indirect Command Execution"},
	{ID: "T1207", Name: "Rogue Domain Controller"},
	{ID: "T1211", Name: "Exploitation for Defense Evasion"},
	{ID: "T1216", Name: "System Script Proxy Execution"},
	{ID: "T1218", Name: "System Binary Proxy Execution"},
	{ID: "T1220", Name: "XSL Script Processing"},
	{ID: "T1221", Name: "Template Injection"},
	{ID: "T1222", Name: "File and Directory Permissions Modification"},
	{ID: "T1480", Name: "Execution Guardrails"},
	{ID: "T1497", Name: "Virtualization/Sandbox Evasion"},
	{ID: "T1550", Name: "Use Alternate Authentication Material"},
	{ID: "T1553", Name: "Subvert Trust Controls"},
	{ID: "T1562", Name: "Impair Defenses"},
	{ID: "T1564", Name: "Hide Artifacts"},
	{ID: "T1578", Name: "Modify Cloud Compute Infrastructure"},
	{ID: "T1599", Name: "Network Boundary Bridging"},
	{ID: "T1600", Name: "Weaken Encryption"},
	{ID: "T1601", Name: "Modify System Image"},
	{ID: "T1612", Name: "Build Image on Host"},
	{ID: "T1620", Name: "Reflective Code Loading"},
	{ID: "T1003", Name: "OS Credential Dumping"},
	{ID: "T1040", Name: "Network Sniffing"},
	{ID: "T1056", Name: "Input Capture"},
	{ID: "T1110", Name: "Brute Force"},
	{ID: "T1111", Name: "Multi-Factor Authentication Interception"},
	{ID: "T1187", Name: "Forced Authentication"},
	{ID: "T1212", Name: "Exploitation for Credential Access"},
	{ID: "T1522", Name: "Cloud Instance Metadata API"},
	{ID: "T1528", Name: "Steal Application Access Token"},
	{ID: "T1539", Name: "Steal Web Session Cookie"},
	{ID: "T1552", Name: "Unsecured Credentials"},
	{ID: "T1555", Name: "Credentials from Password Stores"},
	{ID: "T1557", Name: "Adversary-in-the-Middle"},
	{ID: "T1558", Name: "Steal or Forge Kerberos Tickets"},
	{ID: "T1606", Name: "Forge Web Credentials"},
	{ID: "T1621", Name: "Multi-Factor Authentication Request Generation"},
	{ID: "T1649", Name: "Steal or Forge Authentication Certificates"},
	{ID: "T1007", Name: "System Service Discovery"},
	{ID: "T1010", Name: "Application Window Discovery"},
	{ID: "T1012", Name: "Query Registry"},
	{ID: "T1016", Name: "System Network Configuration Discovery"},
	{ID: "T1018", Name: "Remote System Discovery"},
	{ID: "T1033", Name: "System Owner/User Discovery"},
	{ID: "T1046", Name: "Network Service Discovery"},
	{ID: "T1049", Name: "System Network Connections Discovery"},
	{ID: "T1057", Name: "Process Discovery"},
	{ID: "T1069", Name: "Permission Groups Discovery"},
	{ID: "T1082", Name: "System Information Discovery"},
	{ID: "T1083", Name: "File and Directory Discovery"},
	{ID: "T1087", Name: "Account Discovery"},
	{ID: "T1120", Name: "Peripheral Device Discovery"},
	{ID: "T1124", Name: "System Time Discovery"},
	{ID: "T1135", Name: "Network Share Discovery"},
	{ID: "T1201", Name: "Password Policy Discovery"},
	{ID: "T1217", Name: "Browser Information Discovery"},
	{ID: "T1482", Name: "Domain Trust Discovery"},
	{ID: "T1518", Name: "Software Discovery"},
	{ID: "T1526", Name: "Cloud Service Discovery"},
	{ID: "T1538", Name: "Cloud Service Dashboard"},
	{ID: "T1580", Name: "Cloud Infrastructure Discovery"},
	{ID: "T1613", Name: "Container and Resource Discovery"},
	{ID: "T1614", Name: "System Location Discovery"},
	{ID: "T1615", Name: "Group Policy Discovery"},
	{ID: "T1619", Name: "Cloud Storage Object Discovery"},
	{ID: "T1021", Name: "Remote Services"},
	{ID: "T1080", Name: "Taint Shared Content"},
	{ID: "T1210", Name: "Exploitation of Remote Services"},
	{ID: "T1534", Name: "Internal Spearphishing"},
	{ID: "T1563", Name: "Remote Service Session Hijacking"},
	{ID: "T1570", Name: "Lateral Tool Transfer"},
	{ID: "T1005", Name: "Data from Local System"},
	{ID: "T1025", Name: "Data from Removable Media"},
	{ID: "T1039", Name: "Data from Network Shared Drive"},
	{ID: "T1074", Name: "Data Staged"},
	{ID: "T1113", Name: "Screen Capture"},
	{ID: "T1114", Name: "Email Collection"},
	{ID: "T1115", Name: "Clipboard Data"},
	{ID: "T1119", Name: "Automated Collection"},
	{ID: "T1123", Name: "Audio Capture"},
	{ID: "T1125", Name: "Video Capture"},
	{ID: "T1185", Name: "Browser Session Hijacking"},
	{ID: "T1213", Name: "Data from Information Repositories"},
	{ID: "T1530", Name: "Data from Cloud Storage"},
	{ID: "T1560", Name: "Archive Collected Data"},
	{ID: "T1602", Name: "Data from Configuration Repository"},
	{ID: "T1011", Name: "Exfiltration Over Other Network Medium"},
	{ID: "T1020", Name: "Automated Exfiltration"},
	{ID: "T1029", Name: "Scheduled Transfer"},
	{ID: "T1030", Name: "Data Transfer Size Limits"},
	{ID: "T1041", Name: "Exfiltration Over C2 Channel"},
	{ID: "T1048", Name: "Exfiltration Over Alternative Protocol"},
	{ID: "T1052", Name: "Exfiltration Over Physical Medium"},
	{ID: "T1567", Name: "Exfiltration Over Web Service"},
	{ID: "T1001", Name: "Data Obfuscation"},
	{ID: "T1008", Name: "Fallback Channels"},
	{ID: "T1071", Name: "Application Layer Protocol"},
	{ID: "T1090", Name: "Proxy"},
	{ID: "T1092", Name: "Communication Through Removable Media"},
	{ID: "T1095", Name: "Non-Application Layer Protocol"},
	{ID: "T1102", Name: "Web Service"},
	{ID: "T1104", Name: "Multi-Stage Channels"},
	{ID: "T1105", Name: "Ingress Tool Transfer"},
	{ID: "T1132", Name: "Data Encoding"},
	{ID: "T1219", Name: "Remote Access Software"},
	{ID: "T1568", Name: "Dynamic Resolution"},
	{ID: "T1571", Name: "Non-Standard Port"},
	{ID: "T1572", Name: "Protocol Tunneling"},
	{ID: "T1573", Name: "Encrypted Channel"},
	{ID: "T1485", Name: "Data Destruction"},
	{ID: "T1486", Name: "Data Encrypted for Impact"},
	{ID: "T1489", Name: "Service Stop"},
	{ID: "T1490", Name: "Inhibit System Recovery"},
	{ID: "T1491", Name: "Defacement"},
	{ID: "T1495", Name: "Firmware Corruption"},
	{ID: "T1496", Name: "Resource Hijacking"},
	{ID: "T1498", Name: "Network Denial of Service"},
	{ID: "T1499", Name: "Endpoint Denial of Service"},
	{ID: "T1529", Name: "System Shutdown/Reboot"},
	{ID: "T1531", Name: "Account Access Removal"},
	{ID: "T1561", Name: "Disk Wipe"},
	{ID: "T1565", Name: "Data Manipulation"},
	{ID: "T1583", Name: "Acquire Infrastructure"},
	{ID: "T1584", Name: "Compromise Infrastructure"},
	{ID: "T1585", Name: "Establish Accounts"},
	{ID: "T1586", Name: "Compromise Accounts"},
	{ID: "T1587", Name: "Develop Capabilities"},
	{ID: "T1588", Name: "Obtain Capabilities"},
	{ID: "T1608", Name: "Stage Capabilities"},
	{ID: "T1650", Name: "Acquire Access"},
	{ID: "T1589", Name: "Gather Victim Identity Information"},
	{ID: "T1590", Name: "Gather Victim Network Information"},
	{ID: "T1591", Name: "Gather Victim Org Information"},
	{ID: "T1592", Name: "Gather Victim Host Information"},
	{ID: "T1593", Name: "Search Open Websites/Domains"},
	{ID: "T1594", Name: "Search Victim-Owned Websites"},
	{ID: "T1595", Name: "Active Scanning"},
	{ID: "T1596", Name: "Search Open Technical Databases"},
	{ID: "T1597", Name: "Search Closed Sources"},
	{ID: "T1598", Name: "Phishing for Information"},
	{ID: "T0000", Name: "End"},
}

func (t Technique) Label() string {
	if int(t) >= 0 && int(t) < len(techniqueInfos) {
		return kind.NormalizeString(techniqueInfos[t].Name)
	}
	return kind.NormalizeString(techniqueInfos[TechniqueNone].Name)
}

func (t Technique) String() string {
	return t.Label()
}

func (t Technique) Name() string {
	if int(t) >= 0 && int(t) < len(techniqueInfos) {
		return techniqueInfos[t].Name
	}
	return techniqueInfos[TechniqueNone].Name
}

func (t Technique) ID() string {
	if int(t) >= 0 && int(t) < len(techniqueInfos) {
		return techniqueInfos[t].ID
	}
	return techniqueInfos[TechniqueNone].ID
}

//
// SubTechnique.
//

// revive:disable

type SubTechniqueInfo struct {
	ID   string
	Name string
}

var subTechniqueInfos = []SubTechniqueInfo{
	{ID: "T0000.000", Name: "None"},
	{ID: "T0000.000", Name: "Example"},
	{ID: "T1078.001", Name: "Default Accounts"},
	{ID: "T1078.002", Name: "Domain Accounts"},
	{ID: "T1078.003", Name: "Local Accounts"},
	{ID: "T1078.004", Name: "Cloud Accounts"},
	{ID: "T1195.001", Name: "Compromise Software Dependencies and Development Tools"},
	{ID: "T1195.002", Name: "Compromise Software Supply Chain"},
	{ID: "T1195.003", Name: "Compromise Hardware Supply Chain"},
	{ID: "T1566.001", Name: "Spearphishing Attachment"},
	{ID: "T1566.002", Name: "Spearphishing Link"},
	{ID: "T1566.003", Name: "Spearphishing via Service"},
	{ID: "T1566.004", Name: "Spearphishing Voice"},
	{ID: "T1053.002", Name: "At"},
	{ID: "T1053.003", Name: "Cron"},
	{ID: "T1053.005", Name: "Scheduled Task"},
	{ID: "T1053.006", Name: "Systemd Timers"},
	{ID: "T1053.007", Name: "Container Orchestration Job"},
	{ID: "T1059.001", Name: "PowerShell"},
	{ID: "T1059.002", Name: "AppleScript"},
	{ID: "T1059.003", Name: "Windows Command Shell"},
	{ID: "T1059.004", Name: "Unix Shell"},
	{ID: "T1059.005", Name: "Visual Basic"},
	{ID: "T1059.006", Name: "Python"},
	{ID: "T1059.007", Name: "JavaScript"},
	{ID: "T1059.008", Name: "Network Device CLI"},
	{ID: "T1059.009", Name: "Cloud API"},
	{ID: "T1059.010", Name: "AutoHotKey & AutoIT"},
	{ID: "T1059.011", Name: "Lua"},
	{ID: "T1204.001", Name: "Malicious Link"},
	{ID: "T1204.002", Name: "Malicious File"},
	{ID: "T1204.003", Name: "Malicious Image"},
	{ID: "T1559.001", Name: "Component Object Model"},
	{ID: "T1559.002", Name: "Dynamic Data Exchange"},
	{ID: "T1559.003", Name: "XPC Services"},
	{ID: "T1569.001", Name: "Launchctl"},
	{ID: "T1569.002", Name: "Service Execution"},
	{ID: "T1609.001", Name: "Deploy Container"},
	{ID: "T1037.001", Name: "Logon Script (Windows)"},
	{ID: "T1037.002", Name: "Login Hook"},
	{ID: "T1037.003", Name: "Network Logon Script"},
	{ID: "T1037.004", Name: "RC Scripts"},
	{ID: "T1037.005", Name: "Startup Items"},
	{ID: "T1098.001", Name: "Additional Cloud Credentials"},
	{ID: "T1098.002", Name: "Additional Email Delegate Permissions"},
	{ID: "T1098.003", Name: "Additional Cloud Roles"},
	{ID: "T1098.004", Name: "SSH Authorized Keys"},
	{ID: "T1098.005", Name: "Device Registration"},
	{ID: "T1098.006", Name: "Additional Container Cluster Roles"},
	{ID: "T1098.007", Name: "Additional Local or Domain Groups"},
	{ID: "T1136.001", Name: "Local Account"},
	{ID: "T1136.002", Name: "Domain Account"},
	{ID: "T1136.003", Name: "Cloud Account"},
	{ID: "T1137.001", Name: "Office Template Macros"},
	{ID: "T1137.002", Name: "Office Test"},
	{ID: "T1137.003", Name: "Outlook Forms"},
	{ID: "T1137.004", Name: "Outlook Home Page"},
	{ID: "T1137.005", Name: "Outlook Rules"},
	{ID: "T1137.006", Name: "Add-ins"},
	{ID: "T1205.001", Name: "Port Knocking"},
	{ID: "T1205.002", Name: "Socket Filters"},
	{ID: "T1505.001", Name: "SQL Stored Procedures"},
	{ID: "T1505.002", Name: "Transport Agent"},
	{ID: "T1505.003", Name: "Web Shell"},
	{ID: "T1505.004", Name: "IIS Components"},
	{ID: "T1505.005", Name: "Terminal Services DLL"},
	{ID: "T1542.001", Name: "System Firmware"},
	{ID: "T1542.002", Name: "Component Firmware"},
	{ID: "T1542.003", Name: "Bootkit"},
	{ID: "T1542.004", Name: "ROMMONkit"},
	{ID: "T1542.005", Name: "TFTP Boot"},
	{ID: "T1543.001", Name: "Launch Agent"},
	{ID: "T1543.002", Name: "Systemd Service"},
	{ID: "T1543.003", Name: "Windows Service"},
	{ID: "T1543.004", Name: "Launch Daemon"},
	{ID: "T1543.005", Name: "Container Service"},
	{ID: "T1546.001", Name: "Change Default File Association"},
	{ID: "T1546.002", Name: "Screensaver"},
	{ID: "T1546.003", Name: "Windows Management Instrumentation Event Subscription"},
	{ID: "T1546.004", Name: "Unix Shell Configuration Modification"},
	{ID: "T1546.005", Name: "Trap"},
	{ID: "T1546.006", Name: "LC_LOAD_DYLIB Addition"},
	{ID: "T1546.007", Name: "Netsh Helper DLL"},
	{ID: "T1546.008", Name: "Accessibility Features"},
	{ID: "T1546.009", Name: "AppCert DLLs"},
	{ID: "T1546.010", Name: "AppInit DLLs"},
	{ID: "T1546.011", Name: "Application Shimming"},
	{ID: "T1546.012", Name: "Image File Execution Options Injection"},
	{ID: "T1546.013", Name: "PowerShell Profile"},
	{ID: "T1546.014", Name: "Emond"},
	{ID: "T1546.015", Name: "Component Object Model Hijacking"},
	{ID: "T1546.016", Name: "Installer Packages"},
	{ID: "T1546.017", Name: "Udev Rules"},
	{ID: "T1547.001", Name: "Registry Run Keys / Startup Folder"},
	{ID: "T1547.002", Name: "Authentication Package"},
	{ID: "T1547.003", Name: "Time Providers"},
	{ID: "T1547.004", Name: "Winlogon Helper DLL"},
	{ID: "T1547.005", Name: "Security Support Provider"},
	{ID: "T1547.006", Name: "Kernel Modules and Extensions"},
	{ID: "T1547.007", Name: "Re-opened Applications"},
	{ID: "T1547.008", Name: "LSASS Driver"},
	{ID: "T1547.009", Name: "Shortcut Modification"},
	{ID: "T1547.010", Name: "Port Monitors"},
	{ID: "T1547.011", Name: "Plist Modification"},
	{ID: "T1547.013", Name: "XDG Autostart Entries"},
	{ID: "T1547.014", Name: "Active Setup"},
	{ID: "T1547.015", Name: "Login Items"},
	{ID: "T1556.001", Name: "Domain Controller Authentication"},
	{ID: "T1556.002", Name: "Password Filter DLL"},
	{ID: "T1556.003", Name: "Pluggable Authentication Modules"},
	{ID: "T1556.004", Name: "Network Device Authentication"},
	{ID: "T1556.005", Name: "Reversible Encryption"},
	{ID: "T1556.006", Name: "Multi-Factor Authentication"},
	{ID: "T1556.007", Name: "Hybrid Identity"},
	{ID: "T1556.008", Name: "Network Provider DLL"},
	{ID: "T1556.009", Name: "Conditional Access Policies"},
	{ID: "T1574.001", Name: "DLL Search Order Hijacking"},
	{ID: "T1574.002", Name: "DLL Side-Loading"},
	{ID: "T1574.004", Name: "Dylib Hijacking"},
	{ID: "T1574.005", Name: "Executable Installer File Permissions Weakness"},
	{ID: "T1574.006", Name: "Dynamic Linker Hijacking"},
	{ID: "T1574.007", Name: "Path Interception by PATH Environment Variable"},
	{ID: "T1574.008", Name: "Path Interception by Search Order Hijacking"},
	{ID: "T1574.009", Name: "Path Interception by Unquoted Path"},
	{ID: "T1574.010", Name: "Services File Permissions Weakness"},
	{ID: "T1574.011", Name: "Services Registry Permissions Weakness"},
	{ID: "T1574.012", Name: "COR_PROFILER"},
	{ID: "T1574.013", Name: "KernelCallbackTable"},
	{ID: "T1574.014", Name: "AppDomainManager"},
	{ID: "T1055.001", Name: "Dynamic-link Library Injection"},
	{ID: "T1055.002", Name: "Portable Executable Injection"},
	{ID: "T1055.003", Name: "Thread Execution Hijacking"},
	{ID: "T1055.004", Name: "Asynchronous Procedure Call"},
	{ID: "T1055.005", Name: "Thread Local Storage"},
	{ID: "T1055.008", Name: "Ptrace System Calls"},
	{ID: "T1055.009", Name: "Proc Memory"},
	{ID: "T1055.011", Name: "Extra Window Memory Injection"},
	{ID: "T1055.012", Name: "Process Hollowing"},
	{ID: "T1055.013", Name: "Process Doppelgänging"},
	{ID: "T1055.014", Name: "VDSO Hijacking"},
	{ID: "T1055.015", Name: "ListPlanting"},
	{ID: "T1134.001", Name: "Token Impersonation/Theft"},
	{ID: "T1134.002", Name: "Create Process with Token"},
	{ID: "T1134.003", Name: "Make and Impersonate Token"},
	{ID: "T1134.004", Name: "Parent PID Spoofing"},
	{ID: "T1134.005", Name: "SID-History Injection"},
	{ID: "T1484.001", Name: "Group Policy Modification"},
	{ID: "T1484.002", Name: "Trust Modification"},
	{ID: "T1548.001", Name: "Setuid and Setgid"},
	{ID: "T1548.002", Name: "Bypass User Account Control"},
	{ID: "T1548.003", Name: "Sudo and Sudo Caching"},
	{ID: "T1548.004", Name: "Elevated Execution with Prompt"},
	{ID: "T1548.005", Name: "Temporary Elevated Cloud Access"},
	{ID: "T1548.006", Name: "TCC Manipulation"},
	{ID: "T1027.001", Name: "Binary Padding"},
	{ID: "T1027.002", Name: "Software Packing"},
	{ID: "T1027.003", Name: "Steganography"},
	{ID: "T1027.004", Name: "Compile After Delivery"},
	{ID: "T1027.006", Name: "HTML Smuggling"},
	{ID: "T1036.002", Name: "Right-to-Left Override"},
	{ID: "T1036.003", Name: "Rename System Utilities"},
	{ID: "T1036.004", Name: "Masquerade Task or Service"},
	{ID: "T1036.005", Name: "Match Legitimate Name or Location"},
	{ID: "T1036.006", Name: "Space after Filename"},
	{ID: "T1036.007", Name: "Double File Extension"},
	{ID: "T1036.008", Name: "Masquerade File Type"},
	{ID: "T1070.001", Name: "Clear Windows Event Logs"},
	{ID: "T1070.003", Name: "Clear Command History"},
	{ID: "T1070.004", Name: "File Deletion"},
	{ID: "T1070.006", Name: "Timestomp"},
	{ID: "T1070.007", Name: "Clear Network Connection History and Configurations"},
	{ID: "T1216.001", Name: "PubPrn"},
	{ID: "T1218.001", Name: "Compiled HTML File"},
	{ID: "T1218.002", Name: "Control Panel"},
	{ID: "T1218.003", Name: "CMSTP"},
	{ID: "T1218.004", Name: "InstallUtil"},
	{ID: "T1218.005", Name: "Mshta"},
	{ID: "T1218.007", Name: "Msiexec"},
	{ID: "T1218.008", Name: "Odbcconf"},
	{ID: "T1218.009", Name: "Regsvcs/Regasm"},
	{ID: "T1218.010", Name: "Regsvr32"},
	{ID: "T1218.011", Name: "Rundll32"},
	{ID: "T1218.012", Name: "Verclsid"},
	{ID: "T1218.013", Name: "Mavinject"},
	{ID: "T1218.014", Name: "MMC"},
	{ID: "T1222.001", Name: "Windows File and Directory Permissions Modification"},
	{ID: "T1222.002", Name: "Linux and Mac File and Directory Permissions Modification"},
	{ID: "T1480.001", Name: "Environmental Keying"},
	{ID: "T1480.002", Name: "Mutual Exclusion"},
	{ID: "T1480.003", Name: "Time Based Evasion"},
	{ID: "T1497.001", Name: "System Checks"},
	{ID: "T1497.002", Name: "User Activity Based Checks"},
	{ID: "T1550.001", Name: "Application Access Token"},
	{ID: "T1550.002", Name: "Pass the Hash"},
	{ID: "T1550.003", Name: "Pass the Ticket"},
	{ID: "T1550.004", Name: "Web Session Cookie"},
	{ID: "T1553.001", Name: "Gatekeeper Bypass"},
	{ID: "T1553.002", Name: "Code Signing"},
	{ID: "T1553.003", Name: "SIP and Trust Provider Hijacking"},
	{ID: "T1553.004", Name: "Install Root Certificate"},
	{ID: "T1553.005", Name: "Mark-of-the-Web Bypass"},
	{ID: "T1562.001", Name: "Disable or Modify Tools"},
	{ID: "T1562.002", Name: "Disable Windows Event Logging"},
	{ID: "T1562.004", Name: "Disable or Modify System Firewall"},
	{ID: "T1562.008", Name: "Disable or Modify Cloud Logs"},
	{ID: "T1564.001", Name: "Hidden Files and Directories"},
	{ID: "T1564.002", Name: "Hidden Users"},
	{ID: "T1564.003", Name: "Hidden Window"},
	{ID: "T1564.004", Name: "NTFS File Attributes"},
	{ID: "T1564.005", Name: "Hidden File System"},
	{ID: "T1578.001", Name: "Create Snapshot"},
	{ID: "T1578.002", Name: "Create Cloud Instance"},
	{ID: "T1599.001", Name: "Network Address Translation Traversal"},
	{ID: "T1600.001", Name: "Reduce Key Space"},
	{ID: "T1600.002", Name: "Disable Crypto Hardware"},
	{ID: "T1601.001", Name: "Patch System Image"},
	{ID: "T1601.002", Name: "Downgrade System Image"},
	{ID: "T1003.001", Name: "LSASS Memory"},
	{ID: "T1003.002", Name: "Security Account Manager"},
	{ID: "T1003.003", Name: "NTDS"},
	{ID: "T1003.004", Name: "LSA Secrets"},
	{ID: "T1003.005", Name: "Cached Domain Credentials"},
	{ID: "T1003.006", Name: "DCSync"},
	{ID: "T1003.007", Name: "Proc Filesystem"},
	{ID: "T1056.001", Name: "Keylogging"},
	{ID: "T1056.002", Name: "GUI Input Capture"},
	{ID: "T1056.003", Name: "Web Portal Capture"},
	{ID: "T1110.001", Name: "Password Guessing"},
	{ID: "T1110.002", Name: "Password Cracking"},
	{ID: "T1110.003", Name: "Password Spraying"},
	{ID: "T1110.004", Name: "Credential Stuffing"},
	{ID: "T1552.001", Name: "Credentials In Files"},
	{ID: "T1552.002", Name: "Credentials in Registry"},
	{ID: "T1552.003", Name: "Bash History"},
	{ID: "T1552.006", Name: "Group Policy Preferences"},
	{ID: "T1555.003", Name: "Credentials from Web Browsers"},
	{ID: "T1555.004", Name: "Windows Credential Manager"},
	{ID: "T1555.005", Name: "Password Managers"},
	{ID: "T1557.001", Name: "LLMNR/NBT-NS Poisoning and SMB Relay"},
	{ID: "T1557.002", Name: "ARP Cache Poisoning"},
	{ID: "T1557.003", Name: "DHCP Spoofing"},
	{ID: "T1557.004", Name: "Evil Twin"},
	{ID: "T1558.001", Name: "Golden Ticket"},
	{ID: "T1558.002", Name: "Silver Ticket"},
	{ID: "T1558.003", Name: "Kerberoasting"},
	{ID: "T1606.001", Name: "Web Cookies"},
	{ID: "T1606.002", Name: "SAML Tokens"},
	{ID: "T1016.001", Name: "Internet Connection Discovery"},
	{ID: "T1069.001", Name: "Local Groups"},
	{ID: "T1069.002", Name: "Domain Groups"},
	{ID: "T1069.003", Name: "Cloud Groups"},
	{ID: "T1518.001", Name: "Security Software Discovery"},
	{ID: "T1518.002", Name: "Installed Services Discovery"},
	{ID: "T1614.001", Name: "System Language Discovery"},
	{ID: "T1021.001", Name: "Remote Desktop Protocol"},
	{ID: "T1021.002", Name: "SMB/Windows Admin Shares"},
	{ID: "T1021.003", Name: "Distributed Component Object Model"},
	{ID: "T1021.004", Name: "SSH"},
	{ID: "T1021.005", Name: "VNC"},
	{ID: "T1021.006", Name: "Windows Remote Management"},
	{ID: "T1021.007", Name: "Cloud Services"},
	{ID: "T1563.002", Name: "RDP Hijacking"},
	{ID: "T1074.001", Name: "Local Data Staging"},
	{ID: "T1074.002", Name: "Remote Data Staging"},
	{ID: "T1114.001", Name: "Local Email Collection"},
	{ID: "T1114.002", Name: "Remote Email Collection"},
	{ID: "T1114.003", Name: "Email Forwarding Rule"},
	{ID: "T1213.001", Name: "Confluence"},
	{ID: "T1213.002", Name: "Sharepoint"},
	{ID: "T1213.003", Name: "Code Repositories"},
	{ID: "T1213.004", Name: "Customer Relationship Management Software"},
	{ID: "T1530.001", Name: "Cloud Storage Object"},
	{ID: "T1560.001", Name: "Archive via Utility"},
	{ID: "T1560.002", Name: "Archive via Library"},
	{ID: "T1560.003", Name: "Archive via Custom Method"},
	{ID: "T1602.001", Name: "SNMP (MIB Dump)"},
	{ID: "T1602.002", Name: "Network Device Configuration Dump"},
	{ID: "T1011.001", Name: "Exfiltration Over Bluetooth"},
	{ID: "T1020.001", Name: "Traffic Duplication"},
	{ID: "T1048.001", Name: "Exfiltration Over Symmetric Encrypted Non-C2 Protocol"},
	{ID: "T1048.002", Name: "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"},
	{ID: "T1048.003", Name: "Exfiltration Over Unencrypted Non-C2 Protocol"},
	{ID: "T1052.001", Name: "Exfiltration over USB"},
	{ID: "T1567.001", Name: "Exfiltration to Code Repository"},
	{ID: "T1567.002", Name: "Exfiltration to Cloud Storage"},
	{ID: "T1567.003", Name: "Exfiltration to Text Storage Sites"},
	{ID: "T1567.004", Name: "Exfiltration Over Webhook"},
	{ID: "T1001.001", Name: "Junk Data"},
	{ID: "T1001.003", Name: "Protocol or Service Impersonation"},
	{ID: "T1071.001", Name: "Web Protocols"},
	{ID: "T1071.002", Name: "File Transfer Protocols"},
	{ID: "T1071.003", Name: "Mail Protocols"},
	{ID: "T1071.004", Name: "DNS"},
	{ID: "T1090.001", Name: "Internal Proxy"},
	{ID: "T1090.002", Name: "External Proxy"},
	{ID: "T1090.003", Name: "Multi-hop Proxy"},
	{ID: "T1090.004", Name: "Domain Fronting"},
	{ID: "T1102.001", Name: "Dead Drop Resolver"},
	{ID: "T1102.002", Name: "Bidirectional Communication"},
	{ID: "T1102.003", Name: "One-Way Communication"},
	{ID: "T1132.001", Name: "Standard Encoding"},
	{ID: "T1132.002", Name: "Non-Standard Encoding"},
	{ID: "T1568.001", Name: "Fast Flux DNS"},
	{ID: "T1568.002", Name: "Domain Generation Algorithms"},
	{ID: "T1568.003", Name: "DNS Calculation"},
	{ID: "T1573.001", Name: "Symmetric Cryptography"},
	{ID: "T1573.002", Name: "Asymmetric Cryptography"},
	{ID: "T1485.001", Name: "Lifecycle-Triggered Deletion"},
	{ID: "T1491.001", Name: "Internal Defacement"},
	{ID: "T1491.002", Name: "External Defacement"},
	{ID: "T1496.001", Name: "Compute Hijacking"},
	{ID: "T1498.001", Name: "Direct Network Flood"},
	{ID: "T1498.002", Name: "Reflection Amplification"},
	{ID: "T1499.001", Name: "OS Exhaustion Flood"},
	{ID: "T1499.002", Name: "Service Exhaustion Flood"},
	{ID: "T1499.003", Name: "Application Exhaustion Flood"},
	{ID: "T1499.004", Name: "Application or System Exploitation"},
	{ID: "T1561.001", Name: "Disk Content Wipe"},
	{ID: "T1561.002", Name: "Disk Structure Wipe"},
	{ID: "T1565.001", Name: "Stored Data Manipulation"},
	{ID: "T1565.002", Name: "Transmitted Data Manipulation"},
	{ID: "T1565.003", Name: "Runtime Data Manipulation"},
	{ID: "T1583.001", Name: "Domains"},
	{ID: "T1583.002", Name: "DNS Server"},
	{ID: "T1583.003", Name: "Virtual Private Server"},
	{ID: "T1583.004", Name: "Server"},
	{ID: "T1583.005", Name: "Botnet"},
	{ID: "T1583.006", Name: "Web Services"},
	{ID: "T1583.007", Name: "Serverless"},
	{ID: "T1583.008", Name: "Malvertising"},
	{ID: "T1584.008", Name: "Network Devices"},
	{ID: "T1585.001", Name: "Social Media Accounts"},
	{ID: "T1585.002", Name: "Email Accounts"},
	{ID: "T1587.001", Name: "Malware"},
	{ID: "T1587.002", Name: "Code Signing Certificates"},
	{ID: "T1587.003", Name: "Digital Certificates"},
	{ID: "T1587.004", Name: "Exploits"},
	{ID: "T1588.002", Name: "Tool"},
	{ID: "T1588.006", Name: "Vulnerabilities"},
	{ID: "T1588.007", Name: "Artificial Intelligence"},
	{ID: "T1608.001", Name: "Upload Malware"},
	{ID: "T1608.002", Name: "Upload Tool"},
	{ID: "T1608.003", Name: "Install Digital Certificate"},
	{ID: "T1608.004", Name: "Drive-by Target"},
	{ID: "T1608.005", Name: "Link Target"},
	{ID: "T1608.006", Name: "SEO Poisoning"},
	{ID: "T1589.001", Name: "Credentials"},
	{ID: "T1589.002", Name: "Email Addresses"},
	{ID: "T1589.003", Name: "Employee Names"},
	{ID: "T1590.001", Name: "Domain Properties"},
	{ID: "T1590.003", Name: "Network Trust Dependencies"},
	{ID: "T1590.004", Name: "Network Topology"},
	{ID: "T1590.005", Name: "IP Addresses"},
	{ID: "T1590.006", Name: "Network Security Appliances"},
	{ID: "T1591.001", Name: "Determine Physical Locations"},
	{ID: "T1591.002", Name: "Business Relationships"},
	{ID: "T1591.003", Name: "Identify Business Tempo"},
	{ID: "T1591.004", Name: "Identify Roles"},
	{ID: "T1592.001", Name: "Hardware"},
	{ID: "T1592.002", Name: "Software"},
	{ID: "T1592.003", Name: "Firmware"},
	{ID: "T1592.004", Name: "Client Configurations"},
	{ID: "T1593.001", Name: "Social Media"},
	{ID: "T1593.002", Name: "Search Engines"},
	{ID: "T1595.001", Name: "Scanning IP Blocks"},
	{ID: "T1595.002", Name: "Vulnerability Scanning"},
	{ID: "T1595.003", Name: "Wordlist Scanning"},
	{ID: "T1596.001", Name: "DNS/Passive DNS"},
	{ID: "T1596.002", Name: "WHOIS"},
	{ID: "T1596.004", Name: "CDNs"},
	{ID: "T1596.005", Name: "Scan Databases"},
	{ID: "T1597.001", Name: "Threat Intel Vendors"},
	{ID: "T1597.002", Name: "Purchase Technical Data"},
	{ID: "T1598.001", Name: "Spearphishing Service"},
	{ID: "T0000.000", Name: "End"},
}

type SubTechnique int

const (
	SubTechniqueNone SubTechnique = iota
	SubTechniqueExample
	SubTechniqueDefaultAccounts
	SubTechniqueDomainAccounts
	SubTechniqueLocalAccounts
	SubTechniqueCloudAccounts
	SubTechniqueCompromiseSoftwareDependenciesAndDevelopmentTools
	SubTechniqueCompromiseSoftwareSupplyChain
	SubTechniqueCompromiseHardwareSupplyChain
	SubTechniqueSpearphishingAttachment
	SubTechniqueSpearphishingLink
	SubTechniqueSpearphishingViaService
	SubTechniqueSpearphishingVoice
	SubTechniqueAt
	SubTechniqueCron
	SubTechniqueScheduledTask
	SubTechniqueSystemdTimers
	SubTechniqueContainerOrchestrationJob
	SubTechniquePowershell
	SubTechniqueApplescript
	SubTechniqueWindowsCommandShell
	SubTechniqueUnixShell
	SubTechniqueVisualBasic
	SubTechniquePython
	SubTechniqueJavascript
	SubTechniqueNetworkDeviceCli
	SubTechniqueCloudApi
	SubTechniqueAutohotkeyAutoit
	SubTechniqueLua
	SubTechniqueMaliciousLink
	SubTechniqueMaliciousFile
	SubTechniqueMaliciousImage
	SubTechniqueComponentObjectModel
	SubTechniqueDynamicDataExchange
	SubTechniqueXpcServices
	SubTechniqueLaunchctl
	SubTechniqueServiceExecution
	SubTechniqueDeployContainer
	SubTechniqueLogonScriptWindows
	SubTechniqueLoginHook
	SubTechniqueNetworkLogonScript
	SubTechniqueRcScripts
	SubTechniqueStartupItems
	SubTechniqueAdditionalCloudCredentials
	SubTechniqueAdditionalEmailDelegatePermissions
	SubTechniqueAdditionalCloudRoles
	SubTechniqueSshAuthorizedKeys
	SubTechniqueDeviceRegistration
	SubTechniqueAdditionalContainerClusterRoles
	SubTechniqueAdditionalLocalOrDomainGroups
	SubTechniqueLocalAccount
	SubTechniqueDomainAccount
	SubTechniqueCloudAccount
	SubTechniqueOfficeTemplateMacros
	SubTechniqueOfficeTest
	SubTechniqueOutlookForms
	SubTechniqueOutlookHomePage
	SubTechniqueOutlookRules
	SubTechniqueAddIns
	SubTechniquePortKnocking
	SubTechniqueSocketFilters
	SubTechniqueSqlStoredProcedures
	SubTechniqueTransportAgent
	SubTechniqueWebShell
	SubTechniqueIisComponents
	SubTechniqueTerminalServicesDll
	SubTechniqueSystemFirmware
	SubTechniqueComponentFirmware
	SubTechniqueBootkit
	SubTechniqueRommonkit
	SubTechniqueTftpBoot
	SubTechniqueLaunchAgent
	SubTechniqueSystemdService
	SubTechniqueWindowsService
	SubTechniqueLaunchDaemon
	SubTechniqueContainerService
	SubTechniqueChangeDefaultFileAssociation
	SubTechniqueScreensaver
	SubTechniqueWindowsManagementInstrumentationEventSubscription
	SubTechniqueUnixShellConfigurationModification
	SubTechniqueTrap
	SubTechniqueLcLoadDylibAddition
	SubTechniqueNetshHelperDll
	SubTechniqueAccessibilityFeatures
	SubTechniqueAppcertDlls
	SubTechniqueAppinitDlls
	SubTechniqueApplicationShimming
	SubTechniqueImageFileExecutionOptionsInjection
	SubTechniquePowershellProfile
	SubTechniqueEmond
	SubTechniqueComponentObjectModelHijacking
	SubTechniqueInstallerPackages
	SubTechniqueUdevRules
	SubTechniqueRegistryRunKeysStartupFolder
	SubTechniqueAuthenticationPackage
	SubTechniqueTimeProviders
	SubTechniqueWinlogonHelperDll
	SubTechniqueSecuritySupportProvider
	SubTechniqueKernelModulesAndExtensions
	SubTechniqueReOpenedApplications
	SubTechniqueLsassDriver
	SubTechniqueShortcutModification
	SubTechniquePortMonitors
	SubTechniquePlistModification
	SubTechniqueXdgAutostartEntries
	SubTechniqueActiveSetup
	SubTechniqueLoginItems
	SubTechniqueDomainControllerAuthentication
	SubTechniquePasswordFilterDll
	SubTechniquePluggableAuthenticationModules
	SubTechniqueNetworkDeviceAuthentication
	SubTechniqueReversibleEncryption
	SubTechniqueMultiFactorAuthentication
	SubTechniqueHybridIdentity
	SubTechniqueNetworkProviderDll
	SubTechniqueConditionalAccessPolicies
	SubTechniqueDllSearchOrderHijacking
	SubTechniqueDllSideLoading
	SubTechniqueDylibHijacking
	SubTechniqueExecutableInstallerFilePermissionsWeakness
	SubTechniqueDynamicLinkerHijacking
	SubTechniquePathInterceptionByPathEnvironmentVariable
	SubTechniquePathInterceptionBySearchOrderHijacking
	SubTechniquePathInterceptionByUnquotedPath
	SubTechniqueServicesFilePermissionsWeakness
	SubTechniqueServicesRegistryPermissionsWeakness
	SubTechniqueCorProfiler
	SubTechniqueKernelcallbacktable
	SubTechniqueAppdomainmanager
	SubTechniqueDynamicLinkLibraryInjection
	SubTechniquePortableExecutableInjection
	SubTechniqueThreadExecutionHijacking
	SubTechniqueAsynchronousProcedureCall
	SubTechniqueThreadLocalStorage
	SubTechniquePtraceSystemCalls
	SubTechniqueProcMemory
	SubTechniqueExtraWindowMemoryInjection
	SubTechniqueProcessHollowing
	SubTechniqueProcessDoppelgänging
	SubTechniqueVdsoHijacking
	SubTechniqueListplanting
	SubTechniqueTokenImpersonationTheft
	SubTechniqueCreateProcessWithToken
	SubTechniqueMakeAndImpersonateToken
	SubTechniqueParentPidSpoofing
	SubTechniqueSidHistoryInjection
	SubTechniqueGroupPolicyModification
	SubTechniqueTrustModification
	SubTechniqueSetuidAndSetgid
	SubTechniqueBypassUserAccountControl
	SubTechniqueSudoAndSudoCaching
	SubTechniqueElevatedExecutionWithPrompt
	SubTechniqueTemporaryElevatedCloudAccess
	SubTechniqueTccManipulation
	SubTechniqueBinaryPadding
	SubTechniqueSoftwarePacking
	SubTechniqueSteganography
	SubTechniqueCompileAfterDelivery
	SubTechniqueHtmlSmuggling
	SubTechniqueRightToLeftOverride
	SubTechniqueRenameSystemUtilities
	SubTechniqueMasqueradeTaskOrService
	SubTechniqueMatchLegitimateNameOrLocation
	SubTechniqueSpaceAfterFilename
	SubTechniqueDoubleFileExtension
	SubTechniqueMasqueradeFileType
	SubTechniqueClearWindowsEventLogs
	SubTechniqueClearCommandHistory
	SubTechniqueFileDeletion
	SubTechniqueTimestomp
	SubTechniqueClearNetworkConnectionHistoryAndConfigurations
	SubTechniquePubprn
	SubTechniqueCompiledHtmlFile
	SubTechniqueControlPanel
	SubTechniqueCmstp
	SubTechniqueInstallutil
	SubTechniqueMshta
	SubTechniqueMsiexec
	SubTechniqueOdbcconf
	SubTechniqueRegsvcsRegasm
	SubTechniqueRegsvr32
	SubTechniqueRundll32
	SubTechniqueVerclsid
	SubTechniqueMavinject
	SubTechniqueMmc
	SubTechniqueWindowsFileAndDirectoryPermissionsModification
	SubTechniqueLinuxAndMacFileAndDirectoryPermissionsModification
	SubTechniqueEnvironmentalKeying
	SubTechniqueMutualExclusion
	SubTechniqueTimeBasedEvasion
	SubTechniqueSystemChecks
	SubTechniqueUserActivityBasedChecks
	SubTechniqueApplicationAccessToken
	SubTechniquePassTheHash
	SubTechniquePassTheTicket
	SubTechniqueWebSessionCookie
	SubTechniqueGatekeeperBypass
	SubTechniqueCodeSigning
	SubTechniqueSipAndTrustProviderHijacking
	SubTechniqueInstallRootCertificate
	SubTechniqueMarkOfTheWebBypass
	SubTechniqueDisableOrModifyTools
	SubTechniqueDisableWindowsEventLogging
	SubTechniqueDisableOrModifySystemFirewall
	SubTechniqueDisableOrModifyCloudLogs
	SubTechniqueHiddenFilesAndDirectories
	SubTechniqueHiddenUsers
	SubTechniqueHiddenWindow
	SubTechniqueNtfsFileAttributes
	SubTechniqueHiddenFileSystem
	SubTechniqueCreateSnapshot
	SubTechniqueCreateCloudInstance
	SubTechniqueNetworkAddressTranslationTraversal
	SubTechniqueReduceKeySpace
	SubTechniqueDisableCryptoHardware
	SubTechniquePatchSystemImage
	SubTechniqueDowngradeSystemImage
	SubTechniqueLsassMemory
	SubTechniqueSecurityAccountManager
	SubTechniqueNtds
	SubTechniqueLsaSecrets
	SubTechniqueCachedDomainCredentials
	SubTechniqueDcsync
	SubTechniqueProcFilesystem
	SubTechniqueKeylogging
	SubTechniqueGuiInputCapture
	SubTechniqueWebPortalCapture
	SubTechniquePasswordGuessing
	SubTechniquePasswordCracking
	SubTechniquePasswordSpraying
	SubTechniqueCredentialStuffing
	SubTechniqueCredentialsInFiles
	SubTechniqueCredentialsInRegistry
	SubTechniqueBashHistory
	SubTechniqueGroupPolicyPreferences
	SubTechniqueCredentialsFromWebBrowsers
	SubTechniqueWindowsCredentialManager
	SubTechniquePasswordManagers
	SubTechniqueLlmnrNbtNsPoisoningAndSmbRelay
	SubTechniqueArpCachePoisoning
	SubTechniqueDhcpSpoofing
	SubTechniqueEvilTwin
	SubTechniqueGoldenTicket
	SubTechniqueSilverTicket
	SubTechniqueKerberoasting
	SubTechniqueWebCookies
	SubTechniqueSamlTokens
	SubTechniqueInternetConnectionDiscovery
	SubTechniqueLocalGroups
	SubTechniqueDomainGroups
	SubTechniqueCloudGroups
	SubTechniqueSecuritySoftwareDiscovery
	SubTechniqueInstalledServicesDiscovery
	SubTechniqueSystemLanguageDiscovery
	SubTechniqueRemoteDesktopProtocol
	SubTechniqueSmbWindowsAdminShares
	SubTechniqueDistributedComponentObjectModel
	SubTechniqueSsh
	SubTechniqueVnc
	SubTechniqueWindowsRemoteManagement
	SubTechniqueCloudServices
	SubTechniqueRdpHijacking
	SubTechniqueLocalDataStaging
	SubTechniqueRemoteDataStaging
	SubTechniqueLocalEmailCollection
	SubTechniqueRemoteEmailCollection
	SubTechniqueEmailForwardingRule
	SubTechniqueConfluence
	SubTechniqueSharepoint
	SubTechniqueCodeRepositories
	SubTechniqueCustomerRelationshipManagementSoftware
	SubTechniqueCloudStorageObject
	SubTechniqueArchiveViaUtility
	SubTechniqueArchiveViaLibrary
	SubTechniqueArchiveViaCustomMethod
	SubTechniqueSnmpMibDump
	SubTechniqueNetworkDeviceConfigurationDump
	SubTechniqueExfiltrationOverBluetooth
	SubTechniqueTrafficDuplication
	SubTechniqueExfiltrationOverSymmetricEncryptedNonC2Protocol
	SubTechniqueExfiltrationOverAsymmetricEncryptedNonC2Protocol
	SubTechniqueExfiltrationOverUnencryptedNonC2Protocol
	SubTechniqueExfiltrationOverUsb
	SubTechniqueExfiltrationToCodeRepository
	SubTechniqueExfiltrationToCloudStorage
	SubTechniqueExfiltrationToTextStorageSites
	SubTechniqueExfiltrationOverWebhook
	SubTechniqueJunkData
	SubTechniqueProtocolOrServiceImpersonation
	SubTechniqueWebProtocols
	SubTechniqueFileTransferProtocols
	SubTechniqueMailProtocols
	SubTechniqueDns
	SubTechniqueInternalProxy
	SubTechniqueExternalProxy
	SubTechniqueMultiHopProxy
	SubTechniqueDomainFronting
	SubTechniqueDeadDropResolver
	SubTechniqueBidirectionalCommunication
	SubTechniqueOneWayCommunication
	SubTechniqueStandardEncoding
	SubTechniqueNonStandardEncoding
	SubTechniqueFastFluxDns
	SubTechniqueDomainGenerationAlgorithms
	SubTechniqueDnsCalculation
	SubTechniqueSymmetricCryptography
	SubTechniqueAsymmetricCryptography
	SubTechniqueLifecycleTriggeredDeletion
	SubTechniqueInternalDefacement
	SubTechniqueExternalDefacement
	SubTechniqueComputeHijacking
	SubTechniqueDirectNetworkFlood
	SubTechniqueReflectionAmplification
	SubTechniqueOsExhaustionFlood
	SubTechniqueServiceExhaustionFlood
	SubTechniqueApplicationExhaustionFlood
	SubTechniqueApplicationOrSystemExploitation
	SubTechniqueDiskContentWipe
	SubTechniqueDiskStructureWipe
	SubTechniqueStoredDataManipulation
	SubTechniqueTransmittedDataManipulation
	SubTechniqueRuntimeDataManipulation
	SubTechniqueDomains
	SubTechniqueDnsServer
	SubTechniqueVirtualPrivateServer
	SubTechniqueServer
	SubTechniqueBotnet
	SubTechniqueWebServices
	SubTechniqueServerless
	SubTechniqueMalvertising
	SubTechniqueNetworkDevices
	SubTechniqueSocialMediaAccounts
	SubTechniqueEmailAccounts
	SubTechniqueMalware
	SubTechniqueCodeSigningCertificates
	SubTechniqueDigitalCertificates
	SubTechniqueExploits
	SubTechniqueTool
	SubTechniqueVulnerabilities
	SubTechniqueArtificialIntelligence
	SubTechniqueUploadMalware
	SubTechniqueUploadTool
	SubTechniqueInstallDigitalCertificate
	SubTechniqueDriveByTarget
	SubTechniqueLinkTarget
	SubTechniqueSeoPoisoning
	SubTechniqueCredentials
	SubTechniqueEmailAddresses
	SubTechniqueEmployeeNames
	SubTechniqueDomainProperties
	SubTechniqueNetworkTrustDependencies
	SubTechniqueNetworkTopology
	SubTechniqueIpAddresses
	SubTechniqueNetworkSecurityAppliances
	SubTechniqueDeterminePhysicalLocations
	SubTechniqueBusinessRelationships
	SubTechniqueIdentifyBusinessTempo
	SubTechniqueIdentifyRoles
	SubTechniqueHardware
	SubTechniqueSoftware
	SubTechniqueFirmware
	SubTechniqueClientConfigurations
	SubTechniqueSocialMedia
	SubTechniqueSearchEngines
	SubTechniqueScanningIpBlocks
	SubTechniqueVulnerabilityScanning
	SubTechniqueWordlistScanning
	SubTechniqueDnsPassiveDns
	SubTechniqueWhois
	SubTechniqueCdns
	SubTechniqueScanDatabases
	SubTechniqueThreatIntelVendors
	SubTechniquePurchaseTechnicalData
	SubTechniqueSpearphishingService
	SubTechniqueEnd
)

func (s SubTechnique) Label() string {
	if int(s) >= 0 && int(s) < len(subTechniqueInfos) {
		return kind.NormalizeString(subTechniqueInfos[s].Name)
	}
	return kind.NormalizeString(subTechniqueInfos[SubTechniqueNone].Name)
}

func (s SubTechnique) String() string {
	return s.Label()
}

func (s SubTechnique) Name() string {
	if int(s) >= 0 && int(s) < len(subTechniqueInfos) {
		return subTechniqueInfos[s].Name
	}
	return subTechniqueInfos[SubTechniqueNone].Name
}

func (s SubTechnique) ID() string {
	if int(s) >= 0 && int(s) < len(subTechniqueInfos) {
		return subTechniqueInfos[s].ID
	}
	return subTechniqueInfos[SubTechniqueNone].ID
}
