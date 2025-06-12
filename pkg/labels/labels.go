package labels

import (
	"github.com/garnet-org/jibril-ashkaal/pkg/kind"
)

//
// Metadata.
//

type Metadata struct {
	Kind          kind.Kind
	Version       float64
	Description   string
	Documentation string
	Breed         Breed
	Mechanism     Mechanism
	Tactic        Tactic
	Technique     Technique
	SubTechnique  SubTechnique
}

//
// Importance.
//

type Importance int

const (
	ImportanceNone Importance = iota
	ImportanceLow
	ImportanceMedium
	ImportanceHigh
	ImportanceCritical
	ImportanceEnd
)

func (p Importance) String() string {
	switch p {
	case ImportanceLow:
		return "low"
	case ImportanceMedium:
		return "medium"
	case ImportanceHigh:
		return "high"
	case ImportanceCritical:
		return "critical"
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
	default:
		return "none"
	}
}

//
// Tactic.
//

type Tactic int

// revive:disable

const (
	TacticNone                Tactic = iota //
	TacticExample                           // TA0000 - Example.
	TacticInitialAccess                     // TA0001 - Initial Access: Detect malicious initial access into a system.
	TacticExecution                         // TA0002 - Execution: Detect malicious execution of files or commands.
	TacticPersistence                       // TA0003 - Persistence: Detect malicious persistence mechanisms.
	TacticPrivilegeEscalation               // TA0004 - Privilege Escalation: Detect malicious privilege escalation.
	TacticDefenseEvasion                    // TA0005 - Defense Evasion: Detect malicious defense evasion techniques.
	TacticCredentialAccess                  // TA0006 - Credential Access: Detect malicious credential access.
	TacticDiscovery                         // TA0007 - Discovery: Detect malicious discovery techniques.
	TacticLateralMovement                   // TA0008 - Lateral Movement: Detect malicious lateral movement techniques.
	TacticCollection                        // TA0009 - Collection: Detect malicious collection techniques.
	TacticExfiltration                      // TA0010 - Exfiltration: Detect malicious exfiltration techniques.
	TacticCommandAndControl                 // TA0011 - Command and Control: Detect malicious command and control techniques.
	TacticImpact                            // TA0040 - Impact: Detect malicious impact techniques.
	TacticResourceDevelopment               // TA0042 - Resource Development: Detect malicious resource development.
	TacticReconnaissance                    // TA0043 - Reconnaissance: Detect malicious reconnaissance techniques.
	TacticEnd                               //
)

// revive:enable

func (m Tactic) String() string {
	switch m {
	case TacticNone:
		return "none"
	case TacticExample:
		return "example"
	case TacticEnd:
		return "end"
	case TacticCollection:
		return "collection"
	case TacticCommandAndControl:
		return "command_and_control"
	case TacticCredentialAccess:
		return "credential_access"
	case TacticDefenseEvasion:
		return "defense_evasion"
	case TacticDiscovery:
		return "discovery"
	case TacticExecution:
		return "execution"
	case TacticExfiltration:
		return "exfiltration"
	case TacticImpact:
		return "impact"
	case TacticInitialAccess:
		return "initial_access"
	case TacticLateralMovement:
		return "lateral_movement"
	case TacticPersistence:
		return "persistence"
	case TacticPrivilegeEscalation:
		return "privilege_escalation"
	case TacticReconnaissance:
		return "reconnaissance"
	case TacticResourceDevelopment:
		return "resource_development"
	default:
		return "none"
	}
}

//
// Technique.
//

type Technique int

const (
	TechniqueNone Technique = iota
	TechniqueExample
	TechniqueValidAccounts                              // T1078 - Valid Accounts.
	TechniqueReplicationThroughRemovableMedia           // T1091 - Replication Through Removable Media.
	TechniqueExternalRemoteServices                     // T1133 - External Remote Services.
	TechniqueDriveByCompromise                          // T1189 - Drive-by Compromise.
	TechniqueExploitPublicFacingApplication             // T1190 - Exploit Public-Facing Application.
	TechniqueSupplyChainCompromise                      // T1195 - Supply Chain Compromise
	TechniqueTrustedRelationship                        // T1199 - Trusted Relationship.
	TechniqueHardwareAdditions                          // T1200 - Hardware Additions.
	TechniquePhishing                                   // T1566 - Phishing.
	TechniqueWindowsManagementInstrumentation           // T1047 - Windows Management Instrumentation.
	TechniqueScheduledTaskJob                           // T1053 - Scheduled Task/Job.
	TechniqueCommandAndScriptingInterpreter             // T1059 - Command and Scripting Interpreter.
	TechniqueSoftwareDeploymentTools                    // T1072 - Software Deployment Tools.
	TechniqueNativeApi                                  // T1106 - Native API.
	TechniqueSharedModules                              // T1129 - Shared Modules.
	TechniqueExploitationForClientExecution             // T1203 - Exploitation for Client Execution.
	TechniqueUserExecution                              // T1204 - User Execution.
	TechniqueInterProcessCommunication                  // T1559 - Inter-Process Communication.
	TechniqueSystemServices                             // T1569 - System Services.
	TechniqueContainerAdministrationCommand             // T1609 - Container Administration Command.
	TechniqueServerlessExecution                        // T1648 - Serverless Execution.
	TechniqueCloudAdministrationCommand                 // T1651 - Cloud Administration Command.
	TechniqueBootOrLogonInitializationScripts           // T1037 - Boot or Logon Initialization Scripts.
	TechniqueAccountManipulation                        // T1098 - Account Manipulation.
	TechniqueCreateAccount                              // T1136 - Create Account.
	TechniqueOfficeApplicationStartup                   // T1137 - Office Application Startup.
	TechniqueBrowserExtensions                          // T1176 - Browser Extensions.
	TechniqueBitsJobs                                   // T1197 - BITS Jobs.
	TechniqueTrafficSignaling                           // T1205 - Traffic Signaling.
	TechniqueServerSoftwareComponent                    // T1505 - Server Software Component.
	TechniqueImplantInternalImage                       // T1525 - Implant Internal Image.
	TechniquePreOsBoot                                  // T1542 - Pre-OS Boot.
	TechniqueCreateOrModifySystemProcess                // T1543 - Create or Modify System Process.
	TechniqueEventTriggeredExecution                    // T1546 - Event Triggered Execution.
	TechniqueBootOrLogonAutostartExecution              // T1547 - Boot or Logon Autostart Execution.
	TechniqueCompromiseHostSoftwareBinary               // T1554 - Compromise Host Software Binary.
	TechniqueModifyAuthenticationProcess                // T1556 - Modify Authentication Process.
	TechniqueHijackExecutionFlow                        // T1574 - Hijack Execution Flow.
	TechniqueProcessInjection                           // T1055 - Process Injection.
	TechniqueExploitationForPrivilegeEscalation         // T1068 - Exploitation for Privilege Escalation.
	TechniqueAccessTokenManipulation                    // T1134 - Access Token Manipulation.
	TechniqueDomainOrTenantPolicyModification           // T1484 - Domain or Tenant Policy Modification.
	TechniqueAbuseElevationControlMechanism             // T1548 - Abuse Elevation Control Mechanism.
	TechniqueEscapeToHost                               // T1611 - Escape to Host.
	TechniqueDirectVolumeAccess                         // T1006 - Direct Volume Access.
	TechniqueRootkit                                    // T1014 - Rootkit.
	TechniqueObfuscatedFilesOrInformation               // T1027 - Obfuscated Files or Information.
	TechniqueMasquerading                               // T1036 - Masquerading.
	TechniqueIndicatorRemoval                           // T1070 - Indicator Removal.
	TechniqueModifyRegistry                             // T1112 - Modify Registry.
	TechniqueDeobfuscateDecodeFilesOrInformation        // T1140 - Deobfuscate/Decode Files or Information.
	TechniqueIndirectCommandExecution                   // T1202 - Indirect Command Execution.
	TechniqueRogueDomainController                      // T1207 - Rogue Domain Controller.
	TechniqueExploitationForDefenseEvasion              // T1211 - Exploitation for Defense Evasion.
	TechniqueSystemScriptProxyExecution                 // T1216 - System Script Proxy Execution.
	TechniqueSystemBinaryProxyExecution                 // T1218 - System Binary Proxy Execution.
	TechniqueXslScriptProcessing                        // T1220 - XSL Script Processing.
	TechniqueTemplateInjection                          // T1221 - Template Injection.
	TechniqueFileAndDirectoryPermissionsModification    // T1222 - File and Directory Permissions Modification.
	TechniqueExecutionGuardrails                        // T1480 - Execution Guardrails.
	TechniqueVirtualizationSandboxEvasion               // T1497 - Virtualization/Sandbox Evasion.
	TechniqueUseAlternateAuthenticationMaterial         // T1550 - Use Alternate Authentication Material.
	TechniqueSubvertTrustControls                       // T1553 - Subvert Trust Controls.
	TechniqueImpairDefenses                             // T1562 - Impair Defenses.
	TechniqueHideArtifacts                              // T1564 - Hide Artifacts.
	TechniqueModifyCloudComputeInfrastructure           // T1578 - Modify Cloud Compute Infrastructure.
	TechniqueNetworkBoundaryBridging                    // T1599 - Network Boundary Bridging.
	TechniqueWeakenEncryption                           // T1600 - Weaken Encryption.
	TechniqueModifySystemImage                          // T1601 - Modify System Image.
	TechniqueBuildImageOnHost                           // T1612 - Build Image on Host.
	TechniqueReflectiveCodeLoading                      // T1620 - Reflective Code Loading.
	TechniqueOsCredentialDumping                        // T1003 - OS Credential Dumping.
	TechniqueNetworkSniffing                            // T1040 - Network Sniffing.
	TechniqueInputCapture                               // T1056 - Input Capture.
	TechniqueBruteForce                                 // T1110 - Brute Force.
	TechniqueMultiFactorAuthenticationInterception      // T1111 - Multi-Factor Authentication Interception.
	TechniqueForcedAuthentication                       // T1187 - Forced Authentication.
	TechniqueExploitationForCredentialAccess            // T1212 - Exploitation for Credential Access.
	TechniqueCloudInstanceMetadataApi                   // T1522 - Cloud Instance Metadata API.
	TechniqueStealApplicationAccessToken                // T1528 - Steal Application Access Token.
	TechniqueStealWebSessionCookie                      // T1539 - Steal Web Session Cookie.
	TechniqueUnsecuredCredentials                       // T1552 - Unsecured Credentials.
	TechniqueCredentialsFromPasswordStores              // T1555 - Credentials from Password Stores.
	TechniqueAdversaryInTheMiddle                       // T1557 - Adversary-in-the-Middle.
	TechniqueStealOrForgeKerberosTickets                // T1558 - Steal or Forge Kerberos Tickets.
	TechniqueForgeWebCredentials                        // T1606 - Forge Web Credentials.
	TechniqueMultiFactorAuthenticationRequestGeneration // T1621 - Multi-Factor Authentication Request Generation.
	TechniqueStealOrForgeAuthenticationCertificates     // T1649 - Steal or Forge Authentication Certificates.
	TechniqueSystemServiceDiscovery                     // T1007 - System Service Discovery.
	TechniqueApplicationWindowDiscovery                 // T1010 - Application Window Discovery.
	TechniqueQueryRegistry                              // T1012 - Query Registry.
	TechniqueSystemNetworkConfigurationDiscovery        // T1016 - System Network Configuration Discovery.
	TechniqueRemoteSystemDiscovery                      // T1018 - Remote System Discovery.
	TechniqueSystemOwnerUserDiscovery                   // T1033 - System Owner/User Discovery.
	TechniqueNetworkServiceDiscovery                    // T1046 - Network Service Discovery.
	TechniqueSystemNetworkConnectionsDiscovery          // T1049 - System Network Connections Discovery.
	TechniqueProcessDiscovery                           // T1057 - Process Discovery.
	TechniquePermissionGroupsDiscovery                  // T1069 - Permission Groups Discovery.
	TechniqueSystemInformationDiscovery                 // T1082 - System Information Discovery.
	TechniqueFileAndDirectoryDiscovery                  // T1083 - File and Directory Discovery.
	TechniqueAccountDiscovery                           // T1087 - Account Discovery.
	TechniquePeripheralDeviceDiscovery                  // T1120 - Peripheral Device Discovery.
	TechniqueSystemTimeDiscovery                        // T1124 - System Time Discovery.
	TechniqueNetworkShareDiscovery                      // T1135 - Network Share Discovery.
	TechniquePasswordPolicyDiscovery                    // T1201 - Password Policy Discovery.
	TechniqueBrowserInformationDiscovery                // T1217 - Browser Information Discovery.
	TechniqueDomainTrustDiscovery                       // T1482 - Domain Trust Discovery.
	TechniqueSoftwareDiscovery                          // T1518 - Software Discovery.
	TechniqueCloudServiceDiscovery                      // T1526 - Cloud Service Discovery.
	TechniqueCloudServiceDashboard                      // T1538 - Cloud Service Dashboard.
	TechniqueCloudInfrastructureDiscovery               // T1580 - Cloud Infrastructure Discovery.
	TechniqueContainerAndResourceDiscovery              // T1613 - Container and Resource Discovery.
	TechniqueSystemLocationDiscovery                    // T1614 - System Location Discovery.
	TechniqueGroupPolicyDiscovery                       // T1615 - Group Policy Discovery.
	TechniqueCloudStorageObjectDiscovery                // T1619 - Cloud Storage Object Discovery.
	TechniqueRemoteServices                             // T1021 - Remote Services.
	TechniqueTaintSharedContent                         // T1080 - Taint Shared Content.
	TechniqueExploitationOfRemoteServices               // T1210 - Exploitation of Remote Services.
	TechniqueInternalSpearphishing                      // T1534 - Internal Spearphishing.
	TechniqueRemoteServiceSessionHijacking              // T1563 - Remote Service Session Hijacking.
	TechniqueLateralToolTransfer                        // T1570 - Lateral Tool Transfer.
	TechniqueDataFromLocalSystem                        // T1005 - Data from Local System.
	TechniqueDataFromRemovableMedia                     // T1025 - Data from Removable Media.
	TechniqueDataFromNetworkSharedDrive                 // T1039 - Data from Network Shared Drive.
	TechniqueDataStaged                                 // T1074 - Data Staged.
	TechniqueScreenCapture                              // T1113 - Screen Capture.
	TechniqueEmailCollection                            // T1114 - Email Collection.
	TechniqueClipboardData                              // T1115 - Clipboard Data.
	TechniqueAutomatedCollection                        // T1119 - Automated Collection.
	TechniqueAudioCapture                               // T1123 - Audio Capture.
	TechniqueVideoCapture                               // T1125 - Video Capture.
	TechniqueBrowserSessionHijacking                    // T1185 - Browser Session Hijacking.
	TechniqueDataFromInformationRepositories            // T1213 - Data from Information Repositories.
	TechniqueDataFromCloudStorage                       // T1530 - Data from Cloud Storage.
	TechniqueArchiveCollectedData                       // T1560 - Archive Collected Data.
	TechniqueDataFromConfigurationRepository            // T1602 - Data from Configuration Repository.
	TechniqueExfiltrationOverOtherNetworkMedium         // T1011 - Exfiltration Over Other Network Medium.
	TechniqueAutomatedExfiltration                      // T1020 - Automated Exfiltration.
	TechniqueScheduledTransfer                          // T1029 - Scheduled Transfer.
	TechniqueDataTransferSizeLimits                     // T1030 - Data Transfer Size Limits.
	TechniqueExfiltrationOverC2Channel                  // T1041 - Exfiltration Over C2 Channel.
	TechniqueExfiltrationOverAlternativeProtocol        // T1048 - Exfiltration Over Alternative Protocol.
	TechniqueExfiltrationOverPhysicalMedium             // T1052 - Exfiltration Over Physical Medium.
	TechniqueExfiltrationOverWebService                 // T1567 - Exfiltration Over Web Service.
	TechniqueDataObfuscation                            // T1001 - Data Obfuscation.
	TechniqueFallbackChannels                           // T1008 - Fallback Channels.
	TechniqueApplicationLayerProtocol                   // T1071 - Application Layer Protocol.
	TechniqueProxy                                      // T1090 - Proxy.
	TechniqueCommunicationThroughRemovableMedia         // T1092 - Communication Through Removable Media.
	TechniqueNonApplicationLayerProtocol                // T1095 - Non-Application Layer Protocol.
	TechniqueWebService                                 // T1102 - Web Service.
	TechniqueMultiStageChannels                         // T1104 - Multi-Stage Channels.
	TechniqueIngressToolTransfer                        // T1105 - Ingress Tool Transfer.
	TechniqueDataEncoding                               // T1132 - Data Encoding.
	TechniqueRemoteAccessSoftware                       // T1219 - Remote Access Software.
	TechniqueDynamicResolution                          // T1568 - Dynamic Resolution.
	TechniqueNonStandardPort                            // T1571 - Non-Standard Port.
	TechniqueProtocolTunneling                          // T1572 - Protocol Tunneling.
	TechniqueEncryptedChannel                           // T1573 - Encrypted Channel.
	TechniqueDataDestruction                            // T1485 - Data Destruction.
	TechniqueDataEncryptedForImpact                     // T1486 - Data Encrypted for Impact.
	TechniqueServiceStop                                // T1489 - Service Stop.
	TechniqueInhibitSystemRecovery                      // T1490 - Inhibit System Recovery.
	TechniqueDefacement                                 // T1491 - Defacement.
	TechniqueFirmwareCorruption                         // T1495 - Firmware Corruption.
	TechniqueResourceHijacking                          // T1496 - Resource Hijacking.
	TechniqueNetworkDenialOfService                     // T1498 - Network Denial of Service.
	TechniqueEndpointDenialOfService                    // T1499 - Endpoint Denial of Service.
	TechniqueSystemShutdownReboot                       // T1529 - System Shutdown/Reboot.
	TechniqueAccountAccessRemoval                       // T1531 - Account Access Removal.
	TechniqueDiskWipe                                   // T1561 - Disk Wipe.
	TechniqueDataManipulation                           // T1565 - Data Manipulation.
	TechniqueAcquireInfrastructure                      // T1583 - Acquire Infrastructure.
	TechniqueCompromiseInfrastructure                   // T1584 - Compromise Infrastructure.
	TechniqueEstablishAccounts                          // T1585 - Establish Accounts.
	TechniqueCompromiseAccounts                         // T1586 - Compromise Accounts.
	TechniqueDevelopCapabilities                        // T1587 - Develop Capabilities.
	TechniqueObtainCapabilities                         // T1588 - Obtain Capabilities.
	TechniqueStageCapabilities                          // T1608 - Stage Capabilities.
	TechniqueAcquireAccess                              // T1650 - Acquire Access.
	TechniqueGatherVictimIdentityInformation            // T1589 - Gather Victim Identity Information.
	TechniqueGatherVictimNetworkInformation             // T1590 - Gather Victim Network Information.
	TechniqueGatherVictimOrgInformation                 // T1591 - Gather Victim Org Information.
	TechniqueGatherVictimHostInformation                // T1592 - Gather Victim Host Information.
	TechniqueSearchOpenWebsitesDomains                  // T1593 - Search Open Websites/Domains.
	TechniqueSearchVictimOwnedWebsites                  // T1594 - Search Victim-Owned Websites.
	TechniqueActiveScanning                             // T1595 - Active Scanning.
	TechniqueSearchOpenTechnicalDatabases               // T1596 - Search Open Technical Databases.
	TechniqueSearchClosedSources                        // T1597 - Search Closed Sources.
	TechniquePhishingForInformation                     // T1598 - Phishing for Information.
	TechniqueEnd
)

func (t Technique) String() string {
	switch t {
	case TechniqueNone:
		return "none"
	case TechniqueExample:
		return "example"
	case TechniqueEnd:
		return "end"
	case TechniqueAbuseElevationControlMechanism:
		return "abuse_elevation_control_mechanism"
	case TechniqueAccessTokenManipulation:
		return "access_token_manipulation"
	case TechniqueAccountAccessRemoval:
		return "account_access_removal"
	case TechniqueAccountDiscovery:
		return "account_discovery"
	case TechniqueAccountManipulation:
		return "account_manipulation"
	case TechniqueAcquireAccess:
		return "acquire_access"
	case TechniqueAcquireInfrastructure:
		return "acquire_infrastructure"
	case TechniqueActiveScanning:
		return "active_scanning"
	case TechniqueAdversaryInTheMiddle:
		return "adversary_in_the_middle"
	case TechniqueApplicationLayerProtocol:
		return "application_layer_protocol"
	case TechniqueApplicationWindowDiscovery:
		return "application_window_discovery"
	case TechniqueArchiveCollectedData:
		return "archive_collected_data"
	case TechniqueAudioCapture:
		return "audio_capture"
	case TechniqueAutomatedCollection:
		return "automated_collection"
	case TechniqueAutomatedExfiltration:
		return "automated_exfiltration"
	case TechniqueBitsJobs:
		return "bits_jobs"
	case TechniqueBootOrLogonAutostartExecution:
		return "boot_or_logon_autostart_execution"
	case TechniqueBootOrLogonInitializationScripts:
		return "boot_or_logon_initialization_scripts"
	case TechniqueBrowserExtensions:
		return "browser_extensions"
	case TechniqueBrowserInformationDiscovery:
		return "browser_information_discovery"
	case TechniqueBrowserSessionHijacking:
		return "browser_session_hijacking"
	case TechniqueBruteForce:
		return "brute_force"
	case TechniqueBuildImageOnHost:
		return "build_image_on_host"
	case TechniqueClipboardData:
		return "clipboard_data"
	case TechniqueCloudAdministrationCommand:
		return "cloud_administration_command"
	case TechniqueCloudInfrastructureDiscovery:
		return "cloud_infrastructure_discovery"
	case TechniqueCloudInstanceMetadataApi:
		return "cloud_instance_metadata_api"
	case TechniqueCloudServiceDashboard:
		return "cloud_service_dashboard"
	case TechniqueCloudServiceDiscovery:
		return "cloud_service_discovery"
	case TechniqueCloudStorageObjectDiscovery:
		return "cloud_storage_object_discovery"
	case TechniqueCommandAndScriptingInterpreter:
		return "command_and_scripting_interpreter"
	case TechniqueCommunicationThroughRemovableMedia:
		return "communication_through_removable_media"
	case TechniqueCompromiseAccounts:
		return "compromise_accounts"
	case TechniqueCompromiseHostSoftwareBinary:
		return "compromise_host_software_binary"
	case TechniqueCompromiseInfrastructure:
		return "compromise_infrastructure"
	case TechniqueContainerAdministrationCommand:
		return "container_administration_command"
	case TechniqueContainerAndResourceDiscovery:
		return "container_and_resource_discovery"
	case TechniqueCreateAccount:
		return "create_account"
	case TechniqueCreateOrModifySystemProcess:
		return "create_or_modify_system_process"
	case TechniqueCredentialsFromPasswordStores:
		return "credentials_from_password_stores"
	case TechniqueDataDestruction:
		return "data_destruction"
	case TechniqueDataEncoding:
		return "data_encoding"
	case TechniqueDataEncryptedForImpact:
		return "data_encrypted_for_impact"
	case TechniqueDataFromCloudStorage:
		return "data_from_cloud_storage"
	case TechniqueDataFromConfigurationRepository:
		return "data_from_configuration_repository"
	case TechniqueDataFromInformationRepositories:
		return "data_from_information_repositories"
	case TechniqueDataFromLocalSystem:
		return "data_from_local_system"
	case TechniqueDataFromNetworkSharedDrive:
		return "data_from_network_shared_drive"
	case TechniqueDataFromRemovableMedia:
		return "data_from_removable_media"
	case TechniqueDataManipulation:
		return "data_manipulation"
	case TechniqueDataObfuscation:
		return "data_obfuscation"
	case TechniqueDataStaged:
		return "data_staged"
	case TechniqueDataTransferSizeLimits:
		return "data_transfer_size_limits"
	case TechniqueDefacement:
		return "defacement"
	case TechniqueDeobfuscateDecodeFilesOrInformation:
		return "deobfuscate_decode_files_or_information"
	case TechniqueDevelopCapabilities:
		return "develop_capabilities"
	case TechniqueDirectVolumeAccess:
		return "direct_volume_access"
	case TechniqueDiskWipe:
		return "disk_wipe"
	case TechniqueDomainOrTenantPolicyModification:
		return "domain_or_tenant_policy_modification"
	case TechniqueDomainTrustDiscovery:
		return "domain_trust_discovery"
	case TechniqueDriveByCompromise:
		return "drive_by_compromise"
	case TechniqueDynamicResolution:
		return "dynamic_resolution"
	case TechniqueEmailCollection:
		return "email_collection"
	case TechniqueEncryptedChannel:
		return "encrypted_channel"
	case TechniqueEndpointDenialOfService:
		return "endpoint_denial_of_service"
	case TechniqueEscapeToHost:
		return "escape_to_host"
	case TechniqueEstablishAccounts:
		return "establish_accounts"
	case TechniqueEventTriggeredExecution:
		return "event_triggered_execution"
	case TechniqueExecutionGuardrails:
		return "execution_guardrails"
	case TechniqueExfiltrationOverAlternativeProtocol:
		return "exfiltration_over_alternative_protocol"
	case TechniqueExfiltrationOverC2Channel:
		return "exfiltration_over_c2_channel"
	case TechniqueExfiltrationOverOtherNetworkMedium:
		return "exfiltration_over_other_network_medium"
	case TechniqueExfiltrationOverPhysicalMedium:
		return "exfiltration_over_physical_medium"
	case TechniqueExfiltrationOverWebService:
		return "exfiltration_over_web_service"
	case TechniqueExploitationForClientExecution:
		return "exploitation_for_client_execution"
	case TechniqueExploitationForCredentialAccess:
		return "exploitation_for_credential_access"
	case TechniqueExploitationForDefenseEvasion:
		return "exploitation_for_defense_evasion"
	case TechniqueExploitationForPrivilegeEscalation:
		return "exploitation_for_privilege_escalation"
	case TechniqueExploitationOfRemoteServices:
		return "exploitation_of_remote_services"
	case TechniqueExploitPublicFacingApplication:
		return "exploit_public_facing_application"
	case TechniqueExternalRemoteServices:
		return "external_remote_services"
	case TechniqueFallbackChannels:
		return "fallback_channels"
	case TechniqueFileAndDirectoryDiscovery:
		return "file_and_directory_discovery"
	case TechniqueFileAndDirectoryPermissionsModification:
		return "file_and_directory_permissions_modification"
	case TechniqueFirmwareCorruption:
		return "firmware_corruption"
	case TechniqueForcedAuthentication:
		return "forced_authentication"
	case TechniqueForgeWebCredentials:
		return "forge_web_credentials"
	case TechniqueGatherVictimHostInformation:
		return "gather_victim_host_information"
	case TechniqueGatherVictimIdentityInformation:
		return "gather_victim_identity_information"
	case TechniqueGatherVictimNetworkInformation:
		return "gather_victim_network_information"
	case TechniqueGatherVictimOrgInformation:
		return "gather_victim_org_information"
	case TechniqueGroupPolicyDiscovery:
		return "group_policy_discovery"
	case TechniqueHardwareAdditions:
		return "hardware_additions"
	case TechniqueHideArtifacts:
		return "hide_artifacts"
	case TechniqueHijackExecutionFlow:
		return "hijack_execution_flow"
	case TechniqueImpairDefenses:
		return "impair_defenses"
	case TechniqueImplantInternalImage:
		return "implant_internal_image"
	case TechniqueIndicatorRemoval:
		return "indicator_removal"
	case TechniqueIndirectCommandExecution:
		return "indirect_command_execution"
	case TechniqueIngressToolTransfer:
		return "ingress_tool_transfer"
	case TechniqueInhibitSystemRecovery:
		return "inhibit_system_recovery"
	case TechniqueInputCapture:
		return "input_capture"
	case TechniqueInternalSpearphishing:
		return "internal_spearphishing"
	case TechniqueInterProcessCommunication:
		return "inter_process_communication"
	case TechniqueLateralToolTransfer:
		return "lateral_tool_transfer"
	case TechniqueMasquerading:
		return "masquerading"
	case TechniqueModifyAuthenticationProcess:
		return "modify_authentication_process"
	case TechniqueModifyCloudComputeInfrastructure:
		return "modify_cloud_compute_infrastructure"
	case TechniqueModifyRegistry:
		return "modify_registry"
	case TechniqueModifySystemImage:
		return "modify_system_image"
	case TechniqueMultiFactorAuthenticationInterception:
		return "multi_factor_authentication_interception"
	case TechniqueMultiFactorAuthenticationRequestGeneration:
		return "multi_factor_authentication_request_generation"
	case TechniqueMultiStageChannels:
		return "multi_stage_channels"
	case TechniqueNativeApi:
		return "native_api"
	case TechniqueNetworkBoundaryBridging:
		return "network_boundary_bridging"
	case TechniqueNetworkDenialOfService:
		return "network_denial_of_service"
	case TechniqueNetworkServiceDiscovery:
		return "network_service_discovery"
	case TechniqueNetworkShareDiscovery:
		return "network_share_discovery"
	case TechniqueNetworkSniffing:
		return "network_sniffing"
	case TechniqueNonApplicationLayerProtocol:
		return "non_application_layer_protocol"
	case TechniqueNonStandardPort:
		return "non_standard_port"
	case TechniqueObfuscatedFilesOrInformation:
		return "obfuscated_files_or_information"
	case TechniqueObtainCapabilities:
		return "obtain_capabilities"
	case TechniqueOfficeApplicationStartup:
		return "office_application_startup"
	case TechniqueOsCredentialDumping:
		return "os_credential_dumping"
	case TechniquePasswordPolicyDiscovery:
		return "password_policy_discovery"
	case TechniquePeripheralDeviceDiscovery:
		return "peripheral_device_discovery"
	case TechniquePermissionGroupsDiscovery:
		return "permission_groups_discovery"
	case TechniquePhishingForInformation:
		return "phishing_for_information"
	case TechniquePhishing:
		return "phishing"
	case TechniquePreOsBoot:
		return "pre_os_boot"
	case TechniqueProcessDiscovery:
		return "process_discovery"
	case TechniqueProcessInjection:
		return "process_injection"
	case TechniqueProtocolTunneling:
		return "protocol_tunneling"
	case TechniqueProxy:
		return "proxy"
	case TechniqueQueryRegistry:
		return "query_registry"
	case TechniqueReflectiveCodeLoading:
		return "reflective_code_loading"
	case TechniqueRemoteAccessSoftware:
		return "remote_access_software"
	case TechniqueRemoteServiceSessionHijacking:
		return "remote_service_session_hijacking"
	case TechniqueRemoteServices:
		return "remote_services"
	case TechniqueRemoteSystemDiscovery:
		return "remote_system_discovery"
	case TechniqueReplicationThroughRemovableMedia:
		return "replication_through_removable_media"
	case TechniqueResourceHijacking:
		return "resource_hijacking"
	case TechniqueRogueDomainController:
		return "rogue_domain_controller"
	case TechniqueRootkit:
		return "rootkit"
	case TechniqueScheduledTaskJob:
		return "scheduled_task_job"
	case TechniqueScheduledTransfer:
		return "scheduled_transfer"
	case TechniqueScreenCapture:
		return "screen_capture"
	case TechniqueSearchClosedSources:
		return "search_closed_sources"
	case TechniqueSearchOpenTechnicalDatabases:
		return "search_open_technical_databases"
	case TechniqueSearchOpenWebsitesDomains:
		return "search_open_websites_domains"
	case TechniqueSearchVictimOwnedWebsites:
		return "search_victim_owned_websites"
	case TechniqueServerlessExecution:
		return "serverless_execution"
	case TechniqueServerSoftwareComponent:
		return "server_software_component"
	case TechniqueServiceStop:
		return "service_stop"
	case TechniqueSharedModules:
		return "shared_modules"
	case TechniqueSoftwareDeploymentTools:
		return "software_deployment_tools"
	case TechniqueSoftwareDiscovery:
		return "software_discovery"
	case TechniqueStageCapabilities:
		return "stage_capabilities"
	case TechniqueStealApplicationAccessToken:
		return "steal_application_access_token"
	case TechniqueStealOrForgeAuthenticationCertificates:
		return "steal_or_forge_authentication_certificates"
	case TechniqueStealOrForgeKerberosTickets:
		return "steal_or_forge_kerberos_tickets"
	case TechniqueStealWebSessionCookie:
		return "steal_web_session_cookie"
	case TechniqueSubvertTrustControls:
		return "subvert_trust_controls"
	case TechniqueSupplyChainCompromise:
		return "supply_chain_compromise"
	case TechniqueSystemBinaryProxyExecution:
		return "system_binary_proxy_execution"
	case TechniqueSystemInformationDiscovery:
		return "system_information_discovery"
	case TechniqueSystemLocationDiscovery:
		return "system_location_discovery"
	case TechniqueSystemNetworkConfigurationDiscovery:
		return "system_network_configuration_discovery"
	case TechniqueSystemNetworkConnectionsDiscovery:
		return "system_network_connections_discovery"
	case TechniqueSystemOwnerUserDiscovery:
		return "system_owner_user_discovery"
	case TechniqueSystemScriptProxyExecution:
		return "system_script_proxy_execution"
	case TechniqueSystemServiceDiscovery:
		return "system_service_discovery"
	case TechniqueSystemServices:
		return "system_services"
	case TechniqueSystemShutdownReboot:
		return "system_shutdown_reboot"
	case TechniqueSystemTimeDiscovery:
		return "system_time_discovery"
	case TechniqueTaintSharedContent:
		return "taint_shared_content"
	case TechniqueTemplateInjection:
		return "template_injection"
	case TechniqueTrafficSignaling:
		return "traffic_signaling"
	case TechniqueTrustedRelationship:
		return "trusted_relationship"
	case TechniqueUnsecuredCredentials:
		return "unsecured_credentials"
	case TechniqueUseAlternateAuthenticationMaterial:
		return "use_alternate_authentication_material"
	case TechniqueUserExecution:
		return "user_execution"
	case TechniqueValidAccounts:
		return "valid_accounts"
	case TechniqueVideoCapture:
		return "video_capture"
	case TechniqueVirtualizationSandboxEvasion:
		return "virtualization_sandbox_evasion"
	case TechniqueWeakenEncryption:
		return "weaken_encryption"
	case TechniqueWebService:
		return "web_service"
	case TechniqueWindowsManagementInstrumentation:
		return "windows_management_instrumentation"
	case TechniqueXslScriptProcessing:
		return "xsl_script_processing"
	default:
		return "none"
	}
}

//
// SubTechnique.
//

// revive:disable

type SubTechnique int

const (
	SubTechniqueNone                                               SubTechnique = iota
	SubTechniqueExample                                                         // T0000.000 - Example.
	SubTechniqueDefaultAccounts                                                 // T1078.001 - Default Accounts.
	SubTechniqueDomainAccounts                                                  // T1078.002 - Domain Accounts.
	SubTechniqueLocalAccounts                                                   // T1078.003 - Local Accounts.
	SubTechniqueCloudAccounts                                                   // T1078.004 - Cloud Accounts.
	SubTechniqueCompromiseSoftwareDependenciesAndDevelopmentTools               // T1195.001 - Compromise Software Dependencies and Development Tools.
	SubTechniqueCompromiseSoftwareSupplyChain                                   // T1195.002 - Compromise Software Supply Chain.
	SubTechniqueCompromiseHardwareSupplyChain                                   // T1195.003 - Compromise Hardware Supply Chain.
	SubTechniqueSpearphishingAttachment                                         // T1566.001 - Spearphishing Attachment.
	SubTechniqueSpearphishingLink                                               // T1566.002 - Spearphishing Link.
	SubTechniqueSpearphishingViaService                                         // T1566.003 - Spearphishing via Service.
	SubTechniqueSpearphishingVoice                                              // T1566.004 - Spearphishing Voice.
	SubTechniqueAt                                                              // T1053.002 - At.
	SubTechniqueCron                                                            // T1053.003 - Cron.
	SubTechniqueScheduledTask                                                   // T1053.005 - Scheduled Task.
	SubTechniqueSystemdTimers                                                   // T1053.006 - Systemd Timers.
	SubTechniqueContainerOrchestrationJob                                       // T1053.007 - Container Orchestration Job.
	SubTechniquePowershell                                                      // T1059.001 - PowerShell.
	SubTechniqueApplescript                                                     // T1059.002 - AppleScript.
	SubTechniqueWindowsCommandShell                                             // T1059.003 - Windows Command Shell.
	SubTechniqueUnixShell                                                       // T1059.004 - Unix Shell.
	SubTechniqueVisualBasic                                                     // T1059.005 - Visual Basic.
	SubTechniquePython                                                          // T1059.006 - Python.
	SubTechniqueJavascript                                                      // T1059.007 - JavaScript.
	SubTechniqueNetworkDeviceCli                                                // T1059.008 - Network Device CLI.
	SubTechniqueCloudApi                                                        // T1059.009 - Cloud API.
	SubTechniqueAutohotkeyAutoit                                                // T1059.010 - AutoHotKey & AutoIT.
	SubTechniqueLua                                                             // T1059.011 - Lua.
	SubTechniqueMaliciousLink                                                   // T1204.001 - Malicious Link.
	SubTechniqueMaliciousFile                                                   // T1204.002 - Malicious File.
	SubTechniqueMaliciousImage                                                  // T1204.003 - Malicious Image.
	SubTechniqueComponentObjectModel                                            // T1559.001 - Component Object Model.
	SubTechniqueDynamicDataExchange                                             // T1559.002 - Dynamic Data Exchange.
	SubTechniqueXpcServices                                                     // T1559.003 - XPC Services.
	SubTechniqueLaunchctl                                                       // T1569.001 - Launchctl.
	SubTechniqueServiceExecution                                                // T1569.002 - Service Execution.
	SubTechniqueDeployContainer                                                 // T1609.001 - Deploy Container.
	SubTechniqueLogonScriptWindows                                              // T1037.001 - - Logon Script (Windows) (T1037.001).
	SubTechniqueLoginHook                                                       // T1037.002 - Login Hook.
	SubTechniqueNetworkLogonScript                                              // T1037.003 - Network Logon Script.
	SubTechniqueRcScripts                                                       // T1037.004 - RC Scripts.
	SubTechniqueStartupItems                                                    // T1037.005 - Startup Items.
	SubTechniqueAdditionalCloudCredentials                                      // T1098.001 - Additional Cloud Credentials.
	SubTechniqueAdditionalEmailDelegatePermissions                              // T1098.002 - Additional Email Delegate Permissions.
	SubTechniqueAdditionalCloudRoles                                            // T1098.003 - Additional Cloud Roles.
	SubTechniqueSshAuthorizedKeys                                               // T1098.004 - SSH Authorized Keys.
	SubTechniqueDeviceRegistration                                              // T1098.005 - Device Registration.
	SubTechniqueAdditionalContainerClusterRoles                                 // T1098.006 - Additional Container Cluster Roles.
	SubTechniqueAdditionalLocalOrDomainGroups                                   // T1098.007 - Additional Local or Domain Groups.
	SubTechniqueLocalAccount                                                    // T1136.001 - Local Account.
	SubTechniqueDomainAccount                                                   // T1136.002 - Domain Account.
	SubTechniqueCloudAccount                                                    // T1136.003 - Cloud Account.
	SubTechniqueOfficeTemplateMacros                                            // T1137.001 - Office Template Macros.
	SubTechniqueOfficeTest                                                      // T1137.002 - Office Test.
	SubTechniqueOutlookForms                                                    // T1137.003 - Outlook Forms.
	SubTechniqueOutlookHomePage                                                 // T1137.004 - Outlook Home Page.
	SubTechniqueOutlookRules                                                    // T1137.005 - Outlook Rules.
	SubTechniqueAddIns                                                          // T1137.006 - Add-ins.
	SubTechniquePortKnocking                                                    // T1205.001 - Port Knocking.
	SubTechniqueSocketFilters                                                   // T1205.002 - Socket Filters.
	SubTechniqueSqlStoredProcedures                                             // T1505.001 - SQL Stored Procedures.
	SubTechniqueTransportAgent                                                  // T1505.002 - Transport Agent.
	SubTechniqueWebShell                                                        // T1505.003 - Web Shell.
	SubTechniqueIisComponents                                                   // T1505.004 - IIS Components.
	SubTechniqueTerminalServicesDll                                             // T1505.005 - Terminal Services DLL.
	SubTechniqueSystemFirmware                                                  // T1542.001 - System Firmware.
	SubTechniqueComponentFirmware                                               // T1542.002 - Component Firmware.
	SubTechniqueBootkit                                                         // T1542.003 - Bootkit.
	SubTechniqueRommonkit                                                       // T1542.004 - ROMMONkit.
	SubTechniqueTftpBoot                                                        // T1542.005 - TFTP Boot.
	SubTechniqueLaunchAgent                                                     // T1543.001 - Launch Agent.
	SubTechniqueSystemdService                                                  // T1543.002 - Systemd Service.
	SubTechniqueWindowsService                                                  // T1543.003 - Windows Service.
	SubTechniqueLaunchDaemon                                                    // T1543.004 - Launch Daemon.
	SubTechniqueContainerService                                                // T1543.005 - Container Service.
	SubTechniqueChangeDefaultFileAssociation                                    // T1546.001 - Change Default File Association.
	SubTechniqueScreensaver                                                     // T1546.002 - Screensaver.
	SubTechniqueWindowsManagementInstrumentationEventSubscription               // T1546.003 - Windows Management Instrumentation Event Subscription.
	SubTechniqueUnixShellConfigurationModification                              // T1546.004 - Unix Shell Configuration Modification.
	SubTechniqueTrap                                                            // T1546.005 - Trap.
	SubTechniqueLcLoadDylibAddition                                             // T1546.006 - LC_LOAD_DYLIB Addition.
	SubTechniqueNetshHelperDll                                                  // T1546.007 - Netsh Helper DLL.
	SubTechniqueAccessibilityFeatures                                           // T1546.008 - Accessibility Features.
	SubTechniqueAppcertDlls                                                     // T1546.009 - AppCert DLLs.
	SubTechniqueAppinitDlls                                                     // T1546.010 - AppInit DLLs.
	SubTechniqueApplicationShimming                                             // T1546.011 - Application Shimming.
	SubTechniqueImageFileExecutionOptionsInjection                              // T1546.012 - Image File Execution Options Injection.
	SubTechniquePowershellProfile                                               // T1546.013 - PowerShell Profile.
	SubTechniqueEmond                                                           // T1546.014 - Emond.
	SubTechniqueComponentObjectModelHijacking                                   // T1546.015 - Component Object Model Hijacking.
	SubTechniqueInstallerPackages                                               // T1546.016 - Installer Packages.
	SubTechniqueUdevRules                                                       // T1546.017 - Udev Rules.
	SubTechniqueRegistryRunKeysStartupFolder                                    // T1547.001 - Registry Run Keys / Startup Folder.
	SubTechniqueAuthenticationPackage                                           // T1547.002 - Authentication Package.
	SubTechniqueTimeProviders                                                   // T1547.003 - Time Providers.
	SubTechniqueWinlogonHelperDll                                               // T1547.004 - Winlogon Helper DLL.
	SubTechniqueSecuritySupportProvider                                         // T1547.005 - Security Support Provider.
	SubTechniqueKernelModulesAndExtensions                                      // T1547.006 - Kernel Modules and Extensions.
	SubTechniqueReOpenedApplications                                            // T1547.007 - Re-opened Applications.
	SubTechniqueLsassDriver                                                     // T1547.008 - LSASS Driver.
	SubTechniqueShortcutModification                                            // T1547.009 - Shortcut Modification.
	SubTechniquePortMonitors                                                    // T1547.010 - Port Monitors.
	SubTechniquePlistModification                                               // T1547.011 - Plist Modification.
	SubTechniqueXdgAutostartEntries                                             // T1547.013 - XDG Autostart Entries.
	SubTechniqueActiveSetup                                                     // T1547.014 - Active Setup.
	SubTechniqueLoginItems                                                      // T1547.015 - Login Items.
	SubTechniqueDomainControllerAuthentication                                  // T1556.001 - Domain Controller Authentication.
	SubTechniquePasswordFilterDll                                               // T1556.002 - Password Filter DLL.
	SubTechniquePluggableAuthenticationModules                                  // T1556.003 - Pluggable Authentication Modules.
	SubTechniqueNetworkDeviceAuthentication                                     // T1556.004 - Network Device Authentication.
	SubTechniqueReversibleEncryption                                            // T1556.005 - Reversible Encryption.
	SubTechniqueMultiFactorAuthentication                                       // T1556.006 - Multi-Factor Authentication.
	SubTechniqueHybridIdentity                                                  // T1556.007 - Hybrid Identity.
	SubTechniqueNetworkProviderDll                                              // T1556.008 - Network Provider DLL.
	SubTechniqueConditionalAccessPolicies                                       // T1556.009 - Conditional Access Policies.
	SubTechniqueDllSearchOrderHijacking                                         // T1574.001 - DLL Search Order Hijacking.
	SubTechniqueDllSideLoading                                                  // T1574.002 - DLL Side-Loading.
	SubTechniqueDylibHijacking                                                  // T1574.004 - Dylib Hijacking.
	SubTechniqueExecutableInstallerFilePermissionsWeakness                      // T1574.005 - Executable Installer File Permissions Weakness.
	SubTechniqueDynamicLinkerHijacking                                          // T1574.006 - Dynamic Linker Hijacking.
	SubTechniquePathInterceptionByPathEnvironmentVariable                       // T1574.007 - Path Interception by PATH Environment Variable.
	SubTechniquePathInterceptionBySearchOrderHijacking                          // T1574.008 - Path Interception by Search Order Hijacking.
	SubTechniquePathInterceptionByUnquotedPath                                  // T1574.009 - Path Interception by Unquoted Path.
	SubTechniqueServicesFilePermissionsWeakness                                 // T1574.010 - Services File Permissions Weakness.
	SubTechniqueServicesRegistryPermissionsWeakness                             // T1574.011 - Services Registry Permissions Weakness.
	SubTechniqueCorProfiler                                                     // T1574.012 - COR_PROFILER.
	SubTechniqueKernelcallbacktable                                             // T1574.013 - KernelCallbackTable.
	SubTechniqueAppdomainmanager                                                // T1574.014 - AppDomainManager.
	SubTechniqueDynamicLinkLibraryInjection                                     // T1055.001 - Dynamic-link Library Injection.
	SubTechniquePortableExecutableInjection                                     // T1055.002 - Portable Executable Injection.
	SubTechniqueThreadExecutionHijacking                                        // T1055.003 - Thread Execution Hijacking.
	SubTechniqueAsynchronousProcedureCall                                       // T1055.004 - Asynchronous Procedure Call.
	SubTechniqueThreadLocalStorage                                              // T1055.005 - Thread Local Storage.
	SubTechniquePtraceSystemCalls                                               // T1055.008 - Ptrace System Calls.
	SubTechniqueProcMemory                                                      // T1055.009 - Proc Memory.
	SubTechniqueExtraWindowMemoryInjection                                      // T1055.011 - Extra Window Memory Injection.
	SubTechniqueProcessHollowing                                                // T1055.012 - Process Hollowing.
	SubTechniqueProcessDoppelgänging                                            // T1055.013 - Process Doppelgänging.
	SubTechniqueVdsoHijacking                                                   // T1055.014 - VDSO Hijacking.
	SubTechniqueListplanting                                                    // T1055.015 - ListPlanting.
	SubTechniqueTokenImpersonationTheft                                         // T1134.001 - Token Impersonation/Theft.
	SubTechniqueCreateProcessWithToken                                          // T1134.002 - Create Process with Token.
	SubTechniqueMakeAndImpersonateToken                                         // T1134.003 - Make and Impersonate Token.
	SubTechniqueParentPidSpoofing                                               // T1134.004 - Parent PID Spoofing.
	SubTechniqueSidHistoryInjection                                             // T1134.005 - SID-History Injection.
	SubTechniqueGroupPolicyModification                                         // T1484.001 - Group Policy Modification.
	SubTechniqueTrustModification                                               // T1484.002 - Trust Modification.
	SubTechniqueSetuidAndSetgid                                                 // T1548.001 - Setuid and Setgid.
	SubTechniqueBypassUserAccountControl                                        // T1548.002 - Bypass User Account Control.
	SubTechniqueSudoAndSudoCaching                                              // T1548.003 - Sudo and Sudo Caching.
	SubTechniqueElevatedExecutionWithPrompt                                     // T1548.004 - Elevated Execution with Prompt.
	SubTechniqueTemporaryElevatedCloudAccess                                    // T1548.005 - Temporary Elevated Cloud Access.
	SubTechniqueTccManipulation                                                 // T1548.006 - TCC Manipulation.
	SubTechniqueBinaryPadding                                                   // T1027.001 - Binary Padding.
	SubTechniqueSoftwarePacking                                                 // T1027.002 - Software Packing.
	SubTechniqueSteganography                                                   // T1027.003 - Steganography.
	SubTechniqueCompileAfterDelivery                                            // T1027.004 - Compile After Delivery.
	SubTechniqueHtmlSmuggling                                                   // T1027.006 - HTML Smuggling.
	SubTechniqueRightToLeftOverride                                             // T1036.002 - Right-to-Left Override.
	SubTechniqueRenameSystemUtilities                                           // T1036.003 - Rename System Utilities.
	SubTechniqueMasqueradeTaskOrService                                         // T1036.004 - Masquerade Task or Service.
	SubTechniqueMatchLegitimateNameOrLocation                                   // T1036.005 - Match Legitimate Name or Location.
	SubTechniqueSpaceAfterFilename                                              // T1036.006 - Space after Filename.
	SubTechniqueDoubleFileExtension                                             // T1036.007 - Double File Extension.
	SubTechniqueMasqueradeFileType                                              // T1036.008 - Masquerade File Type.
	SubTechniqueClearWindowsEventLogs                                           // T1070.001 - Clear Windows Event Logs.
	SubTechniqueClearCommandHistory                                             // T1070.003 - Clear Command History.
	SubTechniqueFileDeletion                                                    // T1070.004 - File Deletion.
	SubTechniqueTimestomp                                                       // T1070.006 - Timestomp.
	SubTechniqueClearNetworkConnectionHistoryAndConfigurations                  // T1070.007 - Clear Network Connection History and Configurations.
	SubTechniquePubprn                                                          // T1216.001 - PubPrn.
	SubTechniqueCompiledHtmlFile                                                // T1218.001 - Compiled HTML File.
	SubTechniqueControlPanel                                                    // T1218.002 - Control Panel.
	SubTechniqueCmstp                                                           // T1218.003 - CMSTP.
	SubTechniqueInstallutil                                                     // T1218.004 - InstallUtil.
	SubTechniqueMshta                                                           // T1218.005 - Mshta.
	SubTechniqueMsiexec                                                         // T1218.007 - Msiexec.
	SubTechniqueOdbcconf                                                        // T1218.008 - Odbcconf.
	SubTechniqueRegsvcsRegasm                                                   // T1218.009 - Regsvcs/Regasm.
	SubTechniqueRegsvr32                                                        // T1218.010 - Regsvr32.
	SubTechniqueRundll32                                                        // T1218.011 - Rundll32.
	SubTechniqueVerclsid                                                        // T1218.012 - Verclsid.
	SubTechniqueMavinject                                                       // T1218.013 - Mavinject.
	SubTechniqueMmc                                                             // T1218.014 - MMC.
	SubTechniqueWindowsFileAndDirectoryPermissionsModification                  // T1222.001 - Windows File and Directory Permissions Modification.
	SubTechniqueLinuxAndMacFileAndDirectoryPermissionsModification              // T1222.002 - Linux and Mac File and Directory Permissions Modification.
	SubTechniqueEnvironmentalKeying                                             // T1480.001 - Environmental Keying.
	SubTechniqueMutualExclusion                                                 // T1480.002 - Mutual Exclusion.
	SubTechniqueTimeBasedEvasion                                                // T1480.003 - Time Based Evasion.
	SubTechniqueSystemChecks                                                    // T1497.001 - System Checks.
	SubTechniqueUserActivityBasedChecks                                         // T1497.002 - User Activity Based Checks.
	SubTechniqueApplicationAccessToken                                          // T1550.001 - Application Access Token.
	SubTechniquePassTheHash                                                     // T1550.002 - Pass the Hash.
	SubTechniquePassTheTicket                                                   // T1550.003 - Pass the Ticket.
	SubTechniqueWebSessionCookie                                                // T1550.004 - Web Session Cookie.
	SubTechniqueGatekeeperBypass                                                // T1553.001 - Gatekeeper Bypass.
	SubTechniqueCodeSigning                                                     // T1553.002 - Code Signing.
	SubTechniqueSipAndTrustProviderHijacking                                    // T1553.003 - SIP and Trust Provider Hijacking.
	SubTechniqueInstallRootCertificate                                          // T1553.004 - Install Root Certificate.
	SubTechniqueMarkOfTheWebBypass                                              // T1553.005 - Mark-of-the-Web Bypass.
	SubTechniqueDisableOrModifyTools                                            // T1562.001 - Disable or Modify Tools.
	SubTechniqueDisableWindowsEventLogging                                      // T1562.002 - Disable Windows Event Logging.
	SubTechniqueDisableOrModifySystemFirewall                                   // T1562.004 - Disable or Modify System Firewall.
	SubTechniqueDisableOrModifyCloudLogs                                        // T1562.008 - Disable or Modify Cloud Logs.
	SubTechniqueHiddenFilesAndDirectories                                       // T1564.001 - Hidden Files and Directories.
	SubTechniqueHiddenUsers                                                     // T1564.002 - Hidden Users.
	SubTechniqueHiddenWindow                                                    // T1564.003 - Hidden Window.
	SubTechniqueNtfsFileAttributes                                              // T1564.004 - NTFS File Attributes.
	SubTechniqueHiddenFileSystem                                                // T1564.005 - Hidden File System.
	SubTechniqueCreateSnapshot                                                  // T1578.001 - Create Snapshot.
	SubTechniqueCreateCloudInstance                                             // T1578.002 - Create Cloud Instance.
	SubTechniqueNetworkAddressTranslationTraversal                              // T1599.001 - Network Address Translation Traversal.
	SubTechniqueReduceKeySpace                                                  // T1600.001 - Reduce Key Space.
	SubTechniqueDisableCryptoHardware                                           // T1600.002 - Disable Crypto Hardware.
	SubTechniquePatchSystemImage                                                // T1601.001 - Patch System Image.
	SubTechniqueDowngradeSystemImage                                            // T1601.002 - Downgrade System Image.
	SubTechniqueLsassMemory                                                     // T1003.001 - LSASS Memory.
	SubTechniqueSecurityAccountManager                                          // T1003.002 - Security Account Manager.
	SubTechniqueNtds                                                            // T1003.003 - NTDS.
	SubTechniqueLsaSecrets                                                      // T1003.004 - LSA Secrets.
	SubTechniqueCachedDomainCredentials                                         // T1003.005 - Cached Domain Credentials.
	SubTechniqueDcsync                                                          // T1003.006 - DCSync.
	SubTechniqueProcFilesystem                                                  // T1003.007 - Proc Filesystem.
	SubTechniqueKeylogging                                                      // T1056.001 - Keylogging.
	SubTechniqueGuiInputCapture                                                 // T1056.002 - GUI Input Capture.
	SubTechniqueWebPortalCapture                                                // T1056.003 - Web Portal Capture.
	SubTechniquePasswordGuessing                                                // T1110.001 - Password Guessing.
	SubTechniquePasswordCracking                                                // T1110.002 - Password Cracking.
	SubTechniquePasswordSpraying                                                // T1110.003 - Password Spraying.
	SubTechniqueCredentialStuffing                                              // T1110.004 - Credential Stuffing.
	SubTechniqueCredentialsInFiles                                              // T1552.001 - Credentials In Files.
	SubTechniqueCredentialsInRegistry                                           // T1552.002 - Credentials in Registry.
	SubTechniqueBashHistory                                                     // T1552.003 - Bash History.
	SubTechniqueGroupPolicyPreferences                                          // T1552.006 - Group Policy Preferences.
	SubTechniqueCredentialsFromWebBrowsers                                      // T1555.003 - Credentials from Web Browsers.
	SubTechniqueWindowsCredentialManager                                        // T1555.004 - Windows Credential Manager.
	SubTechniquePasswordManagers                                                // T1555.005 - Password Managers.
	SubTechniqueLlmnrNbtNsPoisoningAndSmbRelay                                  // T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay.
	SubTechniqueArpCachePoisoning                                               // T1557.002 - ARP Cache Poisoning.
	SubTechniqueDhcpSpoofing                                                    // T1557.003 - DHCP Spoofing.
	SubTechniqueEvilTwin                                                        // T1557.004 - Evil Twin.
	SubTechniqueGoldenTicket                                                    // T1558.001 - Golden Ticket.
	SubTechniqueSilverTicket                                                    // T1558.002 - Silver Ticket.
	SubTechniqueKerberoasting                                                   // T1558.003 - Kerberoasting.
	SubTechniqueWebCookies                                                      // T1606.001 - Web Cookies.
	SubTechniqueSamlTokens                                                      // T1606.002 - SAML Tokens.
	SubTechniqueInternetConnectionDiscovery                                     // T1016.001 - Internet Connection Discovery.
	SubTechniqueLocalGroups                                                     // T1069.001 - Local Groups.
	SubTechniqueDomainGroups                                                    // T1069.002 - Domain Groups.
	SubTechniqueCloudGroups                                                     // T1069.003 - Cloud Groups.
	SubTechniqueSecuritySoftwareDiscovery                                       // T1518.001 - Security Software Discovery.
	SubTechniqueInstalledServicesDiscovery                                      // T1518.002 - Installed Services Discovery.
	SubTechniqueSystemLanguageDiscovery                                         // T1614.001 - System Language Discovery.
	SubTechniqueRemoteDesktopProtocol                                           // T1021.001 - Remote Desktop Protocol.
	SubTechniqueSmbWindowsAdminShares                                           // T1021.002 - SMB/Windows Admin Shares.
	SubTechniqueDistributedComponentObjectModel                                 // T1021.003 - Distributed Component Object Model.
	SubTechniqueSsh                                                             // T1021.004 - SSH.
	SubTechniqueVnc                                                             // T1021.005 - VNC.
	SubTechniqueWindowsRemoteManagement                                         // T1021.006 - Windows Remote Management.
	SubTechniqueCloudServices                                                   // T1021.007 - Cloud Services.
	SubTechniqueRdpHijacking                                                    // T1563.002 - RDP Hijacking.
	SubTechniqueLocalDataStaging                                                // T1074.001 - Local Data Staging.
	SubTechniqueRemoteDataStaging                                               // T1074.002 - Remote Data Staging.
	SubTechniqueLocalEmailCollection                                            // T1114.001 - Local Email Collection.
	SubTechniqueRemoteEmailCollection                                           // T1114.002 - Remote Email Collection.
	SubTechniqueEmailForwardingRule                                             // T1114.003 - Email Forwarding Rule.
	SubTechniqueConfluence                                                      // T1213.001 - Confluence.
	SubTechniqueSharepoint                                                      // T1213.002 - Sharepoint.
	SubTechniqueCodeRepositories                                                // T1213.003 - Code Repositories.
	SubTechniqueCustomerRelationshipManagementSoftware                          // T1213.004 - Customer Relationship Management Software.
	SubTechniqueCloudStorageObject                                              // T1530.001 - Cloud Storage Object.
	SubTechniqueArchiveViaUtility                                               // T1560.001 - Archive via Utility.
	SubTechniqueArchiveViaLibrary                                               // T1560.002 - Archive via Library.
	SubTechniqueArchiveViaCustomMethod                                          // T1560.003 - Archive via Custom Method.
	SubTechniqueSnmpMibDump                                                     // T1602.001 - - SNMP (MIB Dump) (T1602.001).
	SubTechniqueNetworkDeviceConfigurationDump                                  // T1602.002 - Network Device Configuration Dump.
	SubTechniqueExfiltrationOverBluetooth                                       // T1011.001 - Exfiltration Over Bluetooth.
	SubTechniqueTrafficDuplication                                              // T1020.001 - Traffic Duplication.
	SubTechniqueExfiltrationOverSymmetricEncryptedNonC2Protocol                 // T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol.
	SubTechniqueExfiltrationOverAsymmetricEncryptedNonC2Protocol                // T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol.
	SubTechniqueExfiltrationOverUnencryptedNonC2Protocol                        // T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol.
	SubTechniqueExfiltrationOverUsb                                             // T1052.001 - Exfiltration over USB.
	SubTechniqueExfiltrationToCodeRepository                                    // T1567.001 - Exfiltration to Code Repository.
	SubTechniqueExfiltrationToCloudStorage                                      // T1567.002 - Exfiltration to Cloud Storage.
	SubTechniqueExfiltrationToTextStorageSites                                  // T1567.003 - Exfiltration to Text Storage Sites.
	SubTechniqueExfiltrationOverWebhook                                         // T1567.004 - Exfiltration Over Webhook.
	SubTechniqueJunkData                                                        // T1001.001 - Junk Data.
	SubTechniqueProtocolOrServiceImpersonation                                  // T1001.003 - Protocol or Service Impersonation.
	SubTechniqueWebProtocols                                                    // T1071.001 - Web Protocols.
	SubTechniqueFileTransferProtocols                                           // T1071.002 - File Transfer Protocols.
	SubTechniqueMailProtocols                                                   // T1071.003 - Mail Protocols.
	SubTechniqueDns                                                             // T1071.004 - DNS.
	SubTechniqueInternalProxy                                                   // T1090.001 - Internal Proxy.
	SubTechniqueExternalProxy                                                   // T1090.002 - External Proxy.
	SubTechniqueMultiHopProxy                                                   // T1090.003 - Multi-hop Proxy.
	SubTechniqueDomainFronting                                                  // T1090.004 - Domain Fronting.
	SubTechniqueDeadDropResolver                                                // T1102.001 - Dead Drop Resolver.
	SubTechniqueBidirectionalCommunication                                      // T1102.002 - Bidirectional Communication.
	SubTechniqueOneWayCommunication                                             // T1102.003 - One-Way Communication.
	SubTechniqueStandardEncoding                                                // T1132.001 - Standard Encoding.
	SubTechniqueNonStandardEncoding                                             // T1132.002 - Non-Standard Encoding.
	SubTechniqueFastFluxDns                                                     // T1568.001 - Fast Flux DNS.
	SubTechniqueDomainGenerationAlgorithms                                      // T1568.002 - Domain Generation Algorithms.
	SubTechniqueDnsCalculation                                                  // T1568.003 - DNS Calculation.
	SubTechniqueSymmetricCryptography                                           // T1573.001 - Symmetric Cryptography.
	SubTechniqueAsymmetricCryptography                                          // T1573.002 - Asymmetric Cryptography.
	SubTechniqueLifecycleTriggeredDeletion                                      // T1485.001 - Lifecycle-Triggered Deletion.
	SubTechniqueInternalDefacement                                              // T1491.001 - Internal Defacement.
	SubTechniqueExternalDefacement                                              // T1491.002 - External Defacement.
	SubTechniqueComputeHijacking                                                // T1496.001 - Compute Hijacking.
	SubTechniqueDirectNetworkFlood                                              // T1498.001 - Direct Network Flood.
	SubTechniqueReflectionAmplification                                         // T1498.002 - Reflection Amplification.
	SubTechniqueOsExhaustionFlood                                               // T1499.001 - OS Exhaustion Flood.
	SubTechniqueServiceExhaustionFlood                                          // T1499.002 - Service Exhaustion Flood.
	SubTechniqueApplicationExhaustionFlood                                      // T1499.003 - Application Exhaustion Flood.
	SubTechniqueApplicationOrSystemExploitation                                 // T1499.004 - Application or System Exploitation.
	SubTechniqueDiskContentWipe                                                 // T1561.001 - Disk Content Wipe.
	SubTechniqueDiskStructureWipe                                               // T1561.002 - Disk Structure Wipe.
	SubTechniqueStoredDataManipulation                                          // T1565.001 - Stored Data Manipulation.
	SubTechniqueTransmittedDataManipulation                                     // T1565.002 - Transmitted Data Manipulation.
	SubTechniqueRuntimeDataManipulation                                         // T1565.003 - Runtime Data Manipulation.
	SubTechniqueDomains                                                         // T1583.001 - Domains.
	SubTechniqueDnsServer                                                       // T1583.002 - DNS Server.
	SubTechniqueVirtualPrivateServer                                            // T1583.003 - Virtual Private Server.
	SubTechniqueServer                                                          // T1583.004 - Server.
	SubTechniqueBotnet                                                          // T1583.005 - Botnet.
	SubTechniqueWebServices                                                     // T1583.006 - Web Services.
	SubTechniqueServerless                                                      // T1583.007 - Serverless.
	SubTechniqueMalvertising                                                    // T1583.008 - Malvertising.
	SubTechniqueNetworkDevices                                                  // T1584.008 - Network Devices.
	SubTechniqueSocialMediaAccounts                                             // T1585.001 - Social Media Accounts.
	SubTechniqueEmailAccounts                                                   // T1585.002 - Email Accounts.
	SubTechniqueMalware                                                         // T1587.001 - Malware.
	SubTechniqueCodeSigningCertificates                                         // T1587.002 - Code Signing Certificates.
	SubTechniqueDigitalCertificates                                             // T1587.003 - Digital Certificates.
	SubTechniqueExploits                                                        // T1587.004 - Exploits.
	SubTechniqueTool                                                            // T1588.002 - Tool.
	SubTechniqueVulnerabilities                                                 // T1588.006 - Vulnerabilities.
	SubTechniqueArtificialIntelligence                                          // T1588.007 - Artificial Intelligence.
	SubTechniqueUploadMalware                                                   // T1608.001 - Upload Malware.
	SubTechniqueUploadTool                                                      // T1608.002 - Upload Tool.
	SubTechniqueInstallDigitalCertificate                                       // T1608.003 - Install Digital Certificate.
	SubTechniqueDriveByTarget                                                   // T1608.004 - Drive-by Target.
	SubTechniqueLinkTarget                                                      // T1608.005 - Link Target.
	SubTechniqueSeoPoisoning                                                    // T1608.006 - SEO Poisoning.
	SubTechniqueCredentials                                                     // T1589.001 - Credentials.
	SubTechniqueEmailAddresses                                                  // T1589.002 - Email Addresses.
	SubTechniqueEmployeeNames                                                   // T1589.003 - Employee Names.
	SubTechniqueDomainProperties                                                // T1590.001 - Domain Properties.
	SubTechniqueNetworkTrustDependencies                                        // T1590.003 - Network Trust Dependencies.
	SubTechniqueNetworkTopology                                                 // T1590.004 - Network Topology.
	SubTechniqueIpAddresses                                                     // T1590.005 - IP Addresses.
	SubTechniqueNetworkSecurityAppliances                                       // T1590.006 - Network Security Appliances.
	SubTechniqueDeterminePhysicalLocations                                      // T1591.001 - Determine Physical Locations.
	SubTechniqueBusinessRelationships                                           // T1591.002 - Business Relationships.
	SubTechniqueIdentifyBusinessTempo                                           // T1591.003 - Identify Business Tempo.
	SubTechniqueIdentifyRoles                                                   // T1591.004 - Identify Roles.
	SubTechniqueHardware                                                        // T1592.001 - Hardware.
	SubTechniqueSoftware                                                        // T1592.002 - Software.
	SubTechniqueFirmware                                                        // T1592.003 - Firmware.
	SubTechniqueClientConfigurations                                            // T1592.004 - Client Configurations.
	SubTechniqueSocialMedia                                                     // T1593.001 - Social Media.
	SubTechniqueSearchEngines                                                   // T1593.002 - Search Engines.
	SubTechniqueScanningIpBlocks                                                // T1595.001 - Scanning IP Blocks.
	SubTechniqueVulnerabilityScanning                                           // T1595.002 - Vulnerability Scanning.
	SubTechniqueWordlistScanning                                                // T1595.003 - Wordlist Scanning.
	SubTechniqueDnsPassiveDns                                                   // T1596.001 - DNS/Passive DNS.
	SubTechniqueWhois                                                           // T1596.002 - WHOIS.
	SubTechniqueCdns                                                            // T1596.004 - CDNs.
	SubTechniqueScanDatabases                                                   // T1596.005 - Scan Databases.
	SubTechniqueThreatIntelVendors                                              // T1597.001 - Threat Intel Vendors.
	SubTechniquePurchaseTechnicalData                                           // T1597.002 - Purchase Technical Data.
	SubTechniqueSpearphishingService                                            // T1598.001 - Spearphishing Service.
	SubTechniqueEnd
)

// revive:enable

func (s SubTechnique) String() string {
	switch s {
	case SubTechniqueNone:
		return "none"
	case SubTechniqueExample:
		return "example"
	case SubTechniqueEnd:
		return "end"
	case SubTechniqueAccessibilityFeatures:
		return "accessibility_features"
	case SubTechniqueActiveSetup:
		return "active_setup"
	case SubTechniqueAddIns:
		return "add_ins"
	case SubTechniqueAdditionalCloudCredentials:
		return "additional_cloud_credentials"
	case SubTechniqueAdditionalCloudRoles:
		return "additional_cloud_roles"
	case SubTechniqueAdditionalContainerClusterRoles:
		return "additional_container_cluster_roles"
	case SubTechniqueAdditionalEmailDelegatePermissions:
		return "additional_email_delegate_permissions"
	case SubTechniqueAdditionalLocalOrDomainGroups:
		return "additional_local_or_domain_groups"
	case SubTechniqueAppcertDlls:
		return "appcert_dlls"
	case SubTechniqueAppdomainmanager:
		return "appdomainmanager"
	case SubTechniqueAppinitDlls:
		return "appinit_dlls"
	case SubTechniqueApplescript:
		return "applescript"
	case SubTechniqueApplicationAccessToken:
		return "application_access_token"
	case SubTechniqueApplicationExhaustionFlood:
		return "application_exhaustion_flood"
	case SubTechniqueApplicationOrSystemExploitation:
		return "application_or_system_exploitation"
	case SubTechniqueApplicationShimming:
		return "application_shimming"
	case SubTechniqueArchiveViaCustomMethod:
		return "archive_via_custom_method"
	case SubTechniqueArchiveViaLibrary:
		return "archive_via_library"
	case SubTechniqueArchiveViaUtility:
		return "archive_via_utility"
	case SubTechniqueArpCachePoisoning:
		return "arp_cache_poisoning"
	case SubTechniqueArtificialIntelligence:
		return "artificial_intelligence"
	case SubTechniqueAsymmetricCryptography:
		return "asymmetric_cryptography"
	case SubTechniqueAsynchronousProcedureCall:
		return "asynchronous_procedure_call"
	case SubTechniqueAt:
		return "at"
	case SubTechniqueAuthenticationPackage:
		return "authentication_package"
	case SubTechniqueAutohotkeyAutoit:
		return "autohotkey_autoit"
	case SubTechniqueBashHistory:
		return "bash_history"
	case SubTechniqueBidirectionalCommunication:
		return "bidirectional_communication"
	case SubTechniqueBinaryPadding:
		return "binary_padding"
	case SubTechniqueBootkit:
		return "bootkit"
	case SubTechniqueBotnet:
		return "botnet"
	case SubTechniqueBusinessRelationships:
		return "business_relationships"
	case SubTechniqueBypassUserAccountControl:
		return "bypass_user_account_control"
	case SubTechniqueCachedDomainCredentials:
		return "cached_domain_credentials"
	case SubTechniqueCdns:
		return "cdns"
	case SubTechniqueChangeDefaultFileAssociation:
		return "change_default_file_association"
	case SubTechniqueClearCommandHistory:
		return "clear_command_history"
	case SubTechniqueClearNetworkConnectionHistoryAndConfigurations:
		return "clear_network_connection_history_and_configurations"
	case SubTechniqueClearWindowsEventLogs:
		return "clear_windows_event_logs"
	case SubTechniqueClientConfigurations:
		return "client_configurations"
	case SubTechniqueCloudAccount:
		return "cloud_account"
	case SubTechniqueCloudAccounts:
		return "cloud_accounts"
	case SubTechniqueCloudApi:
		return "cloud_api"
	case SubTechniqueCloudGroups:
		return "cloud_groups"
	case SubTechniqueCloudServices:
		return "cloud_services"
	case SubTechniqueCloudStorageObject:
		return "cloud_storage_object"
	case SubTechniqueCmstp:
		return "cmstp"
	case SubTechniqueCodeRepositories:
		return "code_repositories"
	case SubTechniqueCodeSigningCertificates:
		return "code_signing_certificates"
	case SubTechniqueCodeSigning:
		return "code_signing"
	case SubTechniqueCompileAfterDelivery:
		return "compile_after_delivery"
	case SubTechniqueCompiledHtmlFile:
		return "compiled_html_file"
	case SubTechniqueComponentFirmware:
		return "component_firmware"
	case SubTechniqueComponentObjectModel:
		return "component_object_model"
	case SubTechniqueComponentObjectModelHijacking:
		return "component_object_model_hijacking"
	case SubTechniqueCompromiseHardwareSupplyChain:
		return "compromise_hardware_supply_chain"
	case SubTechniqueCompromiseSoftwareDependenciesAndDevelopmentTools:
		return "compromise_software_dependencies_and_development_tools"
	case SubTechniqueCompromiseSoftwareSupplyChain:
		return "compromise_software_supply_chain"
	case SubTechniqueComputeHijacking:
		return "compute_hijacking"
	case SubTechniqueConditionalAccessPolicies:
		return "conditional_access_policies"
	case SubTechniqueConfluence:
		return "confluence"
	case SubTechniqueContainerOrchestrationJob:
		return "container_orchestration_job"
	case SubTechniqueContainerService:
		return "container_service"
	case SubTechniqueControlPanel:
		return "control_panel"
	case SubTechniqueCorProfiler:
		return "cor_profiler"
	case SubTechniqueCreateCloudInstance:
		return "create_cloud_instance"
	case SubTechniqueCreateProcessWithToken:
		return "create_process_with_token"
	case SubTechniqueCreateSnapshot:
		return "create_snapshot"
	case SubTechniqueCredentials:
		return "credentials"
	case SubTechniqueCredentialsFromWebBrowsers:
		return "credentials_from_web_browsers"
	case SubTechniqueCredentialsInFiles:
		return "credentials_in_files"
	case SubTechniqueCredentialsInRegistry:
		return "credentials_in_registry"
	case SubTechniqueCredentialStuffing:
		return "credential_stuffing"
	case SubTechniqueCron:
		return "cron"
	case SubTechniqueCustomerRelationshipManagementSoftware:
		return "customer_relationship_management_software"
	case SubTechniqueDcsync:
		return "dcsync"
	case SubTechniqueDeadDropResolver:
		return "dead_drop_resolver"
	case SubTechniqueDefaultAccounts:
		return "default_accounts"
	case SubTechniqueDeployContainer:
		return "deploy_container"
	case SubTechniqueDeterminePhysicalLocations:
		return "determine_physical_locations"
	case SubTechniqueDeviceRegistration:
		return "device_registration"
	case SubTechniqueDhcpSpoofing:
		return "dhcp_spoofing"
	case SubTechniqueDigitalCertificates:
		return "digital_certificates"
	case SubTechniqueDirectNetworkFlood:
		return "direct_network_flood"
	case SubTechniqueDisableCryptoHardware:
		return "disable_crypto_hardware"
	case SubTechniqueDisableOrModifyCloudLogs:
		return "disable_or_modify_cloud_logs"
	case SubTechniqueDisableOrModifySystemFirewall:
		return "disable_or_modify_system_firewall"
	case SubTechniqueDisableOrModifyTools:
		return "disable_or_modify_tools"
	case SubTechniqueDisableWindowsEventLogging:
		return "disable_windows_event_logging"
	case SubTechniqueDiskContentWipe:
		return "disk_content_wipe"
	case SubTechniqueDiskStructureWipe:
		return "disk_structure_wipe"
	case SubTechniqueDistributedComponentObjectModel:
		return "distributed_component_object_model"
	case SubTechniqueDllSearchOrderHijacking:
		return "dll_search_order_hijacking"
	case SubTechniqueDllSideLoading:
		return "dll_side_loading"
	case SubTechniqueDnsCalculation:
		return "dns_calculation"
	case SubTechniqueDns:
		return "dns"
	case SubTechniqueDnsPassiveDns:
		return "dns_passive_dns"
	case SubTechniqueDnsServer:
		return "dns_server"
	case SubTechniqueDomainAccount:
		return "domain_account"
	case SubTechniqueDomainAccounts:
		return "domain_accounts"
	case SubTechniqueDomainControllerAuthentication:
		return "domain_controller_authentication"
	case SubTechniqueDomainFronting:
		return "domain_fronting"
	case SubTechniqueDomainGenerationAlgorithms:
		return "domain_generation_algorithms"
	case SubTechniqueDomainGroups:
		return "domain_groups"
	case SubTechniqueDomainProperties:
		return "domain_properties"
	case SubTechniqueDomains:
		return "domains"
	case SubTechniqueDoubleFileExtension:
		return "double_file_extension"
	case SubTechniqueDowngradeSystemImage:
		return "downgrade_system_image"
	case SubTechniqueDriveByTarget:
		return "drive_by_target"
	case SubTechniqueDylibHijacking:
		return "dylib_hijacking"
	case SubTechniqueDynamicDataExchange:
		return "dynamic_data_exchange"
	case SubTechniqueDynamicLinkerHijacking:
		return "dynamic_linker_hijacking"
	case SubTechniqueDynamicLinkLibraryInjection:
		return "dynamic_link_library_injection"
	case SubTechniqueElevatedExecutionWithPrompt:
		return "elevated_execution_with_prompt"
	case SubTechniqueEmailAccounts:
		return "email_accounts"
	case SubTechniqueEmailAddresses:
		return "email_addresses"
	case SubTechniqueEmailForwardingRule:
		return "email_forwarding_rule"
	case SubTechniqueEmond:
		return "emond"
	case SubTechniqueEmployeeNames:
		return "employee_names"
	case SubTechniqueEnvironmentalKeying:
		return "environmental_keying"
	case SubTechniqueEvilTwin:
		return "evil_twin"
	case SubTechniqueExecutableInstallerFilePermissionsWeakness:
		return "executable_installer_file_permissions_weakness"
	case SubTechniqueExfiltrationOverAsymmetricEncryptedNonC2Protocol:
		return "exfiltration_over_asymmetric_encrypted_non_c2_protocol"
	case SubTechniqueExfiltrationOverBluetooth:
		return "exfiltration_over_bluetooth"
	case SubTechniqueExfiltrationOverSymmetricEncryptedNonC2Protocol:
		return "exfiltration_over_symmetric_encrypted_non_c2_protocol"
	case SubTechniqueExfiltrationOverUnencryptedNonC2Protocol:
		return "exfiltration_over_unencrypted_non_c2_protocol"
	case SubTechniqueExfiltrationOverUsb:
		return "exfiltration_over_usb"
	case SubTechniqueExfiltrationOverWebhook:
		return "exfiltration_over_webhook"
	case SubTechniqueExfiltrationToCloudStorage:
		return "exfiltration_to_cloud_storage"
	case SubTechniqueExfiltrationToCodeRepository:
		return "exfiltration_to_code_repository"
	case SubTechniqueExfiltrationToTextStorageSites:
		return "exfiltration_to_text_storage_sites"
	case SubTechniqueExploits:
		return "exploits"
	case SubTechniqueExternalDefacement:
		return "external_defacement"
	case SubTechniqueExternalProxy:
		return "external_proxy"
	case SubTechniqueExtraWindowMemoryInjection:
		return "extra_window_memory_injection"
	case SubTechniqueFastFluxDns:
		return "fast_flux_dns"
	case SubTechniqueFileDeletion:
		return "file_deletion"
	case SubTechniqueFileTransferProtocols:
		return "file_transfer_protocols"
	case SubTechniqueFirmware:
		return "firmware"
	case SubTechniqueGatekeeperBypass:
		return "gatekeeper_bypass"
	case SubTechniqueGoldenTicket:
		return "golden_ticket"
	case SubTechniqueGroupPolicyModification:
		return "group_policy_modification"
	case SubTechniqueGroupPolicyPreferences:
		return "group_policy_preferences"
	case SubTechniqueGuiInputCapture:
		return "gui_input_capture"
	case SubTechniqueHardware:
		return "hardware"
	case SubTechniqueHiddenFilesAndDirectories:
		return "hidden_files_and_directories"
	case SubTechniqueHiddenFileSystem:
		return "hidden_file_system"
	case SubTechniqueHiddenUsers:
		return "hidden_users"
	case SubTechniqueHiddenWindow:
		return "hidden_window"
	case SubTechniqueHtmlSmuggling:
		return "html_smuggling"
	case SubTechniqueHybridIdentity:
		return "hybrid_identity"
	case SubTechniqueIdentifyBusinessTempo:
		return "identify_business_tempo"
	case SubTechniqueIdentifyRoles:
		return "identify_roles"
	case SubTechniqueIisComponents:
		return "iis_components"
	case SubTechniqueImageFileExecutionOptionsInjection:
		return "image_file_execution_options_injection"
	case SubTechniqueInstallDigitalCertificate:
		return "install_digital_certificate"
	case SubTechniqueInstalledServicesDiscovery:
		return "installed_services_discovery"
	case SubTechniqueInstallerPackages:
		return "installer_packages"
	case SubTechniqueInstallRootCertificate:
		return "install_root_certificate"
	case SubTechniqueInstallutil:
		return "installutil"
	case SubTechniqueInternalDefacement:
		return "internal_defacement"
	case SubTechniqueInternalProxy:
		return "internal_proxy"
	case SubTechniqueInternetConnectionDiscovery:
		return "internet_connection_discovery"
	case SubTechniqueIpAddresses:
		return "ip_addresses"
	case SubTechniqueJavascript:
		return "javascript"
	case SubTechniqueJunkData:
		return "junk_data"
	case SubTechniqueKerberoasting:
		return "kerberoasting"
	case SubTechniqueKernelcallbacktable:
		return "kernelcallbacktable"
	case SubTechniqueKernelModulesAndExtensions:
		return "kernel_modules_and_extensions"
	case SubTechniqueKeylogging:
		return "keylogging"
	case SubTechniqueLaunchAgent:
		return "launch_agent"
	case SubTechniqueLaunchctl:
		return "launchctl"
	case SubTechniqueLaunchDaemon:
		return "launch_daemon"
	case SubTechniqueLcLoadDylibAddition:
		return "lc_load_dylib_addition"
	case SubTechniqueLifecycleTriggeredDeletion:
		return "lifecycle_triggered_deletion"
	case SubTechniqueLinkTarget:
		return "link_target"
	case SubTechniqueLinuxAndMacFileAndDirectoryPermissionsModification:
		return "linux_and_mac_file_and_directory_permissions_modification"
	case SubTechniqueListplanting:
		return "listplanting"
	case SubTechniqueLlmnrNbtNsPoisoningAndSmbRelay:
		return "llmnr_nbt_ns_poisoning_and_smb_relay"
	case SubTechniqueLocalAccount:
		return "local_account"
	case SubTechniqueLocalAccounts:
		return "local_accounts"
	case SubTechniqueLocalDataStaging:
		return "local_data_staging"
	case SubTechniqueLocalEmailCollection:
		return "local_email_collection"
	case SubTechniqueLocalGroups:
		return "local_groups"
	case SubTechniqueLoginHook:
		return "login_hook"
	case SubTechniqueLoginItems:
		return "login_items"
	case SubTechniqueLogonScriptWindows:
		return "logon_script_windows"
	case SubTechniqueLsaSecrets:
		return "lsa_secrets"
	case SubTechniqueLsassDriver:
		return "lsass_driver"
	case SubTechniqueLsassMemory:
		return "lsass_memory"
	case SubTechniqueLua:
		return "lua"
	case SubTechniqueMailProtocols:
		return "mail_protocols"
	case SubTechniqueMakeAndImpersonateToken:
		return "make_and_impersonate_token"
	case SubTechniqueMaliciousFile:
		return "malicious_file"
	case SubTechniqueMaliciousImage:
		return "malicious_image"
	case SubTechniqueMaliciousLink:
		return "malicious_link"
	case SubTechniqueMalvertising:
		return "malvertising"
	case SubTechniqueMalware:
		return "malware"
	case SubTechniqueMarkOfTheWebBypass:
		return "mark_of_the_web_bypass"
	case SubTechniqueMasqueradeFileType:
		return "masquerade_file_type"
	case SubTechniqueMasqueradeTaskOrService:
		return "masquerade_task_or_service"
	case SubTechniqueMatchLegitimateNameOrLocation:
		return "match_legitimate_name_or_location"
	case SubTechniqueMavinject:
		return "mavinject"
	case SubTechniqueMmc:
		return "mmc"
	case SubTechniqueMshta:
		return "mshta"
	case SubTechniqueMsiexec:
		return "msiexec"
	case SubTechniqueMultiFactorAuthentication:
		return "multi_factor_authentication"
	case SubTechniqueMultiHopProxy:
		return "multi_hop_proxy"
	case SubTechniqueMutualExclusion:
		return "mutual_exclusion"
	case SubTechniqueNetshHelperDll:
		return "netsh_helper_dll"
	case SubTechniqueNetworkAddressTranslationTraversal:
		return "network_address_translation_traversal"
	case SubTechniqueNetworkDeviceAuthentication:
		return "network_device_authentication"
	case SubTechniqueNetworkDeviceCli:
		return "network_device_cli"
	case SubTechniqueNetworkDeviceConfigurationDump:
		return "network_device_configuration_dump"
	case SubTechniqueNetworkDevices:
		return "network_devices"
	case SubTechniqueNetworkLogonScript:
		return "network_logon_script"
	case SubTechniqueNetworkProviderDll:
		return "network_provider_dll"
	case SubTechniqueNetworkSecurityAppliances:
		return "network_security_appliances"
	case SubTechniqueNetworkTopology:
		return "network_topology"
	case SubTechniqueNetworkTrustDependencies:
		return "network_trust_dependencies"
	case SubTechniqueNonStandardEncoding:
		return "non_standard_encoding"
	case SubTechniqueNtds:
		return "ntds"
	case SubTechniqueNtfsFileAttributes:
		return "ntfs_file_attributes"
	case SubTechniqueOdbcconf:
		return "odbcconf"
	case SubTechniqueOfficeTemplateMacros:
		return "office_template_macros"
	case SubTechniqueOfficeTest:
		return "office_test"
	case SubTechniqueOneWayCommunication:
		return "one_way_communication"
	case SubTechniqueOsExhaustionFlood:
		return "os_exhaustion_flood"
	case SubTechniqueOutlookForms:
		return "outlook_forms"
	case SubTechniqueOutlookHomePage:
		return "outlook_home_page"
	case SubTechniqueOutlookRules:
		return "outlook_rules"
	case SubTechniqueParentPidSpoofing:
		return "parent_pid_spoofing"
	case SubTechniquePassTheHash:
		return "pass_the_hash"
	case SubTechniquePassTheTicket:
		return "pass_the_ticket"
	case SubTechniquePasswordCracking:
		return "password_cracking"
	case SubTechniquePasswordFilterDll:
		return "password_filter_dll"
	case SubTechniquePasswordGuessing:
		return "password_guessing"
	case SubTechniquePasswordManagers:
		return "password_managers"
	case SubTechniquePasswordSpraying:
		return "password_spraying"
	case SubTechniquePatchSystemImage:
		return "patch_system_image"
	case SubTechniquePathInterceptionByPathEnvironmentVariable:
		return "path_interception_by_path_environment_variable"
	case SubTechniquePathInterceptionBySearchOrderHijacking:
		return "path_interception_by_search_order_hijacking"
	case SubTechniquePathInterceptionByUnquotedPath:
		return "path_interception_by_unquoted_path"
	case SubTechniquePlistModification:
		return "plist_modification"
	case SubTechniquePluggableAuthenticationModules:
		return "pluggable_authentication_modules"
	case SubTechniquePortableExecutableInjection:
		return "portable_executable_injection"
	case SubTechniquePortKnocking:
		return "port_knocking"
	case SubTechniquePortMonitors:
		return "port_monitors"
	case SubTechniquePowershell:
		return "powershell"
	case SubTechniquePowershellProfile:
		return "powershell_profile"
	case SubTechniqueProcessDoppelgänging:
		return "process_doppelgänging"
	case SubTechniqueProcessHollowing:
		return "process_hollowing"
	case SubTechniqueProcFilesystem:
		return "proc_filesystem"
	case SubTechniqueProcMemory:
		return "proc_memory"
	case SubTechniqueProtocolOrServiceImpersonation:
		return "protocol_or_service_impersonation"
	case SubTechniquePtraceSystemCalls:
		return "ptrace_system_calls"
	case SubTechniquePubprn:
		return "pubprn"
	case SubTechniquePurchaseTechnicalData:
		return "purchase_technical_data"
	case SubTechniquePython:
		return "python"
	case SubTechniqueRcScripts:
		return "rc_scripts"
	case SubTechniqueRdpHijacking:
		return "rdp_hijacking"
	case SubTechniqueReduceKeySpace:
		return "reduce_key_space"
	case SubTechniqueReflectionAmplification:
		return "reflection_amplification"
	case SubTechniqueRegistryRunKeysStartupFolder:
		return "registry_run_keys_startup_folder"
	case SubTechniqueRegsvcsRegasm:
		return "regsvcs_regasm"
	case SubTechniqueRegsvr32:
		return "regsvr32"
	case SubTechniqueRemoteDataStaging:
		return "remote_data_staging"
	case SubTechniqueRemoteDesktopProtocol:
		return "remote_desktop_protocol"
	case SubTechniqueRemoteEmailCollection:
		return "remote_email_collection"
	case SubTechniqueRenameSystemUtilities:
		return "rename_system_utilities"
	case SubTechniqueReOpenedApplications:
		return "re_opened_applications"
	case SubTechniqueReversibleEncryption:
		return "reversible_encryption"
	case SubTechniqueRightToLeftOverride:
		return "right_to_left_override"
	case SubTechniqueRommonkit:
		return "rommonkit"
	case SubTechniqueRundll32:
		return "rundll32"
	case SubTechniqueRuntimeDataManipulation:
		return "runtime_data_manipulation"
	case SubTechniqueSamlTokens:
		return "saml_tokens"
	case SubTechniqueScanDatabases:
		return "scan_databases"
	case SubTechniqueScanningIpBlocks:
		return "scanning_ip_blocks"
	case SubTechniqueScheduledTask:
		return "scheduled_task"
	case SubTechniqueScreensaver:
		return "screensaver"
	case SubTechniqueSearchEngines:
		return "search_engines"
	case SubTechniqueSecurityAccountManager:
		return "security_account_manager"
	case SubTechniqueSecuritySoftwareDiscovery:
		return "security_software_discovery"
	case SubTechniqueSecuritySupportProvider:
		return "security_support_provider"
	case SubTechniqueSeoPoisoning:
		return "seo_poisoning"
	case SubTechniqueServerless:
		return "serverless"
	case SubTechniqueServer:
		return "server"
	case SubTechniqueServiceExecution:
		return "service_execution"
	case SubTechniqueServiceExhaustionFlood:
		return "service_exhaustion_flood"
	case SubTechniqueServicesFilePermissionsWeakness:
		return "services_file_permissions_weakness"
	case SubTechniqueServicesRegistryPermissionsWeakness:
		return "services_registry_permissions_weakness"
	case SubTechniqueSetuidAndSetgid:
		return "setuid_and_setgid"
	case SubTechniqueSharepoint:
		return "sharepoint"
	case SubTechniqueShortcutModification:
		return "shortcut_modification"
	case SubTechniqueSidHistoryInjection:
		return "sid_history_injection"
	case SubTechniqueSilverTicket:
		return "silver_ticket"
	case SubTechniqueSipAndTrustProviderHijacking:
		return "sip_and_trust_provider_hijacking"
	case SubTechniqueSmbWindowsAdminShares:
		return "smb_windows_admin_shares"
	case SubTechniqueSnmpMibDump:
		return "snmp_mib_dump"
	case SubTechniqueSocialMediaAccounts:
		return "social_media_accounts"
	case SubTechniqueSocialMedia:
		return "social_media"
	case SubTechniqueSocketFilters:
		return "socket_filters"
	case SubTechniqueSoftwarePacking:
		return "software_packing"
	case SubTechniqueSoftware:
		return "software"
	case SubTechniqueSpaceAfterFilename:
		return "space_after_filename"
	case SubTechniqueSpearphishingAttachment:
		return "spearphishing_attachment"
	case SubTechniqueSpearphishingLink:
		return "spearphishing_link"
	case SubTechniqueSpearphishingService:
		return "spearphishing_service"
	case SubTechniqueSpearphishingViaService:
		return "spearphishing_via_service"
	case SubTechniqueSpearphishingVoice:
		return "spearphishing_voice"
	case SubTechniqueSqlStoredProcedures:
		return "sql_stored_procedures"
	case SubTechniqueSshAuthorizedKeys:
		return "ssh_authorized_keys"
	case SubTechniqueSsh:
		return "ssh"
	case SubTechniqueStandardEncoding:
		return "standard_encoding"
	case SubTechniqueStartupItems:
		return "startup_items"
	case SubTechniqueSteganography:
		return "steganography"
	case SubTechniqueStoredDataManipulation:
		return "stored_data_manipulation"
	case SubTechniqueSudoAndSudoCaching:
		return "sudo_and_sudo_caching"
	case SubTechniqueSymmetricCryptography:
		return "symmetric_cryptography"
	case SubTechniqueSystemChecks:
		return "system_checks"
	case SubTechniqueSystemdService:
		return "systemd_service"
	case SubTechniqueSystemdTimers:
		return "systemd_timers"
	case SubTechniqueSystemFirmware:
		return "system_firmware"
	case SubTechniqueSystemLanguageDiscovery:
		return "system_language_discovery"
	case SubTechniqueTccManipulation:
		return "tcc_manipulation"
	case SubTechniqueTemporaryElevatedCloudAccess:
		return "temporary_elevated_cloud_access"
	case SubTechniqueTerminalServicesDll:
		return "terminal_services_dll"
	case SubTechniqueTftpBoot:
		return "tftp_boot"
	case SubTechniqueThreadExecutionHijacking:
		return "thread_execution_hijacking"
	case SubTechniqueThreadLocalStorage:
		return "thread_local_storage"
	case SubTechniqueThreatIntelVendors:
		return "threat_intel_vendors"
	case SubTechniqueTimeBasedEvasion:
		return "time_based_evasion"
	case SubTechniqueTimeProviders:
		return "time_providers"
	case SubTechniqueTimestomp:
		return "timestomp"
	case SubTechniqueTokenImpersonationTheft:
		return "token_impersonation_theft"
	case SubTechniqueTool:
		return "tool"
	case SubTechniqueTrafficDuplication:
		return "traffic_duplication"
	case SubTechniqueTransmittedDataManipulation:
		return "transmitted_data_manipulation"
	case SubTechniqueTransportAgent:
		return "transport_agent"
	case SubTechniqueTrap:
		return "trap"
	case SubTechniqueTrustModification:
		return "trust_modification"
	case SubTechniqueUdevRules:
		return "udev_rules"
	case SubTechniqueUnixShellConfigurationModification:
		return "unix_shell_configuration_modification"
	case SubTechniqueUnixShell:
		return "unix_shell"
	case SubTechniqueUploadMalware:
		return "upload_malware"
	case SubTechniqueUploadTool:
		return "upload_tool"
	case SubTechniqueUserActivityBasedChecks:
		return "user_activity_based_checks"
	case SubTechniqueVdsoHijacking:
		return "vdso_hijacking"
	case SubTechniqueVerclsid:
		return "verclsid"
	case SubTechniqueVirtualPrivateServer:
		return "virtual_private_server"
	case SubTechniqueVisualBasic:
		return "visual_basic"
	case SubTechniqueVnc:
		return "vnc"
	case SubTechniqueVulnerabilities:
		return "vulnerabilities"
	case SubTechniqueVulnerabilityScanning:
		return "vulnerability_scanning"
	case SubTechniqueWebCookies:
		return "web_cookies"
	case SubTechniqueWebPortalCapture:
		return "web_portal_capture"
	case SubTechniqueWebProtocols:
		return "web_protocols"
	case SubTechniqueWebServices:
		return "web_services"
	case SubTechniqueWebSessionCookie:
		return "web_session_cookie"
	case SubTechniqueWebShell:
		return "web_shell"
	case SubTechniqueWhois:
		return "whois"
	case SubTechniqueWindowsCommandShell:
		return "windows_command_shell"
	case SubTechniqueWindowsCredentialManager:
		return "windows_credential_manager"
	case SubTechniqueWindowsFileAndDirectoryPermissionsModification:
		return "windows_file_and_directory_permissions_modification"
	case SubTechniqueWindowsManagementInstrumentationEventSubscription:
		return "windows_management_instrumentation_event_subscription"
	case SubTechniqueWindowsRemoteManagement:
		return "windows_remote_management"
	case SubTechniqueWindowsService:
		return "windows_service"
	case SubTechniqueWinlogonHelperDll:
		return "winlogon_helper_dll"
	case SubTechniqueWordlistScanning:
		return "wordlist_scanning"
	case SubTechniqueXdgAutostartEntries:
		return "xdg_autostart_entries"
	case SubTechniqueXpcServices:
		return "xpc_services"
	default:
		return "none"
	}
}
