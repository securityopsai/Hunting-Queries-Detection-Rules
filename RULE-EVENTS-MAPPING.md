# Rule to Events Mapping

This table maps every detection/hunting rule in this repository to the **events** it operates on. Because rules here are authored as KQL inside Markdown (`.md`) files — there are no JSON rule definitions — the events are derived directly from each rule's KQL:

- **Tables / Data Sources**: the distinct KQL table names the query reads from (e.g. `DeviceProcessEvents`, `EmailEvents`, `AuditLogs`, `externaldata` for MISP feeds). Detected from statement-start references, `union`/`join` sources, `let` sources, and a curated known-tables list.
- **Event Filters**: the specific event values selected within those tables via `ActionType == "..."`, `OperationName == "..."`, `Operation == "..."`, and their `in (...)` list forms. Blank when the rule does not filter on a specific event type.

Generated deterministically by `build_rule_events_mapping.py`. Rules processed: **282**.

| Rule | Category | Tables / Data Sources | Event Filters |
| --- | --- | --- | --- |
| Azure/Arc/LastCheckInArcMachines.md | Azure | Heartbeat |  |
| Azure/Arc/MachineOnboarded.md | Azure | AzureActivity |  |
| Azure/Arc/OnboardedMachinesByResourceGroup.md | Azure | — |  |
| Azure/Compute/LargeNumberOfVMsStarted.md | Azure | AzureActivity |  |
| Azure Active Directory/ADRoleAdditions.md | Azure Active Directory | AuditLogs | Add member to role |
| Azure Active Directory/AllGraphPermissionsAdded.md | Azure Active Directory | AuditLogs |  |
| Azure Active Directory/AzureADDownloadAllUsers.md | Azure Active Directory | AuditLogs |  |
| Azure Active Directory/CloudDiscoveryByUserAtRisk.md | Azure Active Directory | AADRiskyUsers, AuditLogs |  |
| Azure Active Directory/CloudPersistenceActivityByUserAtRisk.md | Azure Active Directory | AADRiskyUsers, AuditLogs |  |
| Azure Active Directory/ConditionalAccess - AddPolicy.md | Azure Active Directory | AuditLogs | Add conditional access policy |
| Azure Active Directory/ConditionalAccess - ApplicationFailures.md | Azure Active Directory | SigninLogs |  |
| Azure Active Directory/ConditionalAccess - ChangePolicy.md | Azure Active Directory | AuditLogs | Update conditional access policy |
| Azure Active Directory/ConditionalAccess - DeletePolicy.md | Azure Active Directory | AuditLogs | Delete conditional access policy |
| Azure Active Directory/ConditionalAccess - UserFailures.md | Azure Active Directory | SigninLogs |  |
| Azure Active Directory/GraphMailPermissions.md | Azure Active Directory | AuditLogs | Add delegated permission grant |
| Azure Active Directory/GroupMembershipReport.md | Azure Active Directory | IdentityInfo |  |
| Azure Active Directory/GuestUsersWithADRoles.md | Azure Active Directory | IdentityInfo |  |
| Azure Active Directory/MultipleAccountsLocked.md | Azure Active Directory | SigninLogs |  |
| Azure Active Directory/NewAuthenticationAppDetected.md | Azure Active Directory | AADSignInEventsBeta, SigninLogs |  |
| Azure Active Directory/NewUserAgentUsed.md | Azure Active Directory | AADSignInEventsBeta, SigninLogs |  |
| Azure Active Directory/PotentialAiTMPhishing.md | Azure Active Directory | AADSignInEventsBeta, SigninLogs |  |
| Azure Active Directory/RoleReport.md | Azure Active Directory | IdentityInfo |  |
| Azure Active Directory/SecurityAlertTriggeredByRiskyUser.md | Azure Active Directory | AADRiskyUsers, SecurityAlert |  |
| Azure Active Directory/SignInFromSuspiciousIP.md | Azure Active Directory | AADSignInEventsBeta, SigninLogs, ThreatIntelligenceIndicator |  |
| Azure Active Directory/SignInsByBrowser.md | Azure Active Directory | SigninLogs |  |
| Azure Active Directory/SignInsByOS.md | Azure Active Directory | AADSignInEventsBeta, SigninLogs |  |
| Azure Active Directory/SignInsByUserAgent.md | Azure Active Directory | AADSignInEventsBeta, SigninLogs |  |
| Azure Active Directory/SuccessfulDeviceCodeAuthenticationUnmanagedDevice.md | Azure Active Directory | AADSignInEventsBeta, SigninLogs |  |
| Azure Active Directory/SuccessfulSignInFromNewCountry.md | Azure Active Directory | AADSignInEventsBeta, SigninLogs |  |
| Azure Active Directory/Top10UsersWithTheMostSignInIPsUsed.md | Azure Active Directory | AADSignInEventsBeta, SigninLogs |  |
| Azure Active Directory/TopNAccountsLongestPeriodWithoutPasswordReset.md | Azure Active Directory | AADSignInEventsBeta |  |
| Azure Active Directory/TotalAllGraphPermissionsAdded.md | Azure Active Directory | AuditLogs | Add delegated permission grant |
| Azure Active Directory/Visualization - AccountsLongestPeriodWithoutPasswordReset.md | Azure Active Directory | AADSignInEventsBeta |  |
| Azure Active Directory/Visualization - AuthenticationMethodsUsed.md | Azure Active Directory | SigninLogs |  |
| Azure Active Directory/Visualization - ConditionalAccess - SignInFailures.md | Azure Active Directory | SigninLogs |  |
| Azure Active Directory/Visualization - PimActivation.md | Azure Active Directory | AuditLogs | Add member to role completed (PIM activation) |
| Azure Active Directory/Visualization - UserRiskEvents.md | Azure Active Directory | AADUserRiskEvents |  |
| Cloud Audit Events/CloudResourceDeletion.md | Cloud Audit Events | CloudAuditEvents | CloudAuditEventDelete |
| Defender For Cloud Apps/AccountsWithMostImpersonatedActions.md | Defender For Cloud Apps | CloudAppEvents |  |
| Defender For Cloud Apps/ATPDetectionEvents.md | Defender For Cloud Apps | CloudAppEvents | AtpDetection |
| Defender For Cloud Apps/DefenseEvasionAlerts.md | Defender For Cloud Apps | CloudAppEvents | DefenseEvasion |
| Defender For Cloud Apps/DisabledAccountAttackDisruption.md | Defender For Cloud Apps | CloudAppEvents | Disable account. |
| Defender For Cloud Apps/ExternalAdminActivities.md | Defender For Cloud Apps | CloudAppEvents |  |
| Defender For Cloud Apps/FileContainingMalwareDetected.md | Defender For Cloud Apps | CloudAppEvents | FileMalwareDetected |
| Defender For Cloud Apps/HardUserDelete.md | Defender For Cloud Apps | CloudAppEvents | Hard Delete user. |
| Defender For Cloud Apps/MaliciousEmailDeliveredInMailbox.md | Defender For Cloud Apps | CloudAppEvents, EmailEvents | TIMailData-Inline |
| Defender For Cloud Apps/MostImpersonatorsByAccount.md | Defender For Cloud Apps | CloudAppEvents |  |
| Defender For Cloud Apps/OAuthAppInfo/ApplicationMailPermission.md | Defender For Cloud Apps | OAuthAppInfo |  |
| Defender For Cloud Apps/OAuthAppInfo/ExternalApplicationHighPrivPermissions.md | Defender For Cloud Apps | OAuthAppInfo |  |
| Defender For Cloud Apps/OAuthAppInfo/MostUserConsentApplication.md | Defender For Cloud Apps | OAuthAppInfo |  |
| Defender For Cloud Apps/OAuthAppInfo/UnusedHighPrivPermissions.md | Defender For Cloud Apps | OAuthAppInfo |  |
| Defender For Cloud Apps/OneDriveSyncFromRareIP.md | Defender For Cloud Apps | AADSignInEventsBeta, CloudAppEvents, SigninLogs | FileSyncUploadedFull |
| Defender For Cloud Apps/RiskyIPActivities.md | Defender For Cloud Apps | CloudAppEvents |  |
| Defender For Cloud Apps/SupressionRuleCreations.md | Defender For Cloud Apps | CloudAppEvents | Write AlertsSuppressionRules |
| Defender For Endpoint/AMSIScriptDetections.md | Defender For Endpoint | DeviceEvents | AmsiScriptDetection |
| Defender For Endpoint/AnomalousSMBSessionsCreated.md | Defender For Endpoint | DeviceNetworkEvents |  |
| Defender For Endpoint/ASR Rules/AsrRansomware.md | Defender For Endpoint | DeviceEvents | AsrRansomwareAudited, AsrRansomwareBlocked |
| Defender For Endpoint/BloodHoundProcessDetection.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/CommandlineGroupAddition.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/CommandlineUserAddition.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/CommandlineWithClearTextPassword.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/DefenderDiscoveryActivities.md | Defender For Endpoint | DeviceEvents, DeviceProcessEvents |  |
| Defender For Endpoint/Detect_Known_RAT_RMM_Process_Patterns.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/DevicesWithMostSMBConnections.md | Defender For Endpoint | DeviceNetworkEvents | ConnectionSuccess |
| Defender For Endpoint/DevicesWithTheMostSMBSessions.md | Defender For Endpoint | DeviceNetworkEvents |  |
| Defender For Endpoint/Discovery - DatabaseServices.md | Defender For Endpoint | DeviceNetworkEvents |  |
| Defender For Endpoint/ExecutableFilesProgramDataFolder.md | Defender For Endpoint | DeviceFileEvents |  |
| Defender For Endpoint/ExecutableFilesPublicFolder.md | Defender For Endpoint | DeviceFileEvents |  |
| Defender For Endpoint/ExploitGuardNetworkProtection.md | Defender For Endpoint | DeviceEvents | ExploitGuardNetworkProtectionAudited, ExploitGuardNetworkProtectionBlocked |
| Defender For Endpoint/HTTPDownloadsByFileExtention.md | Defender For Endpoint | DeviceNetworkEvents | NetworkSignatureInspected |
| Defender For Endpoint/HTTPExecutableFilesDownloaded.md | Defender For Endpoint | DeviceNetworkEvents | NetworkSignatureInspected |
| Defender For Endpoint/HTTPRequestMethodsStatistics.md | Defender For Endpoint | DeviceNetworkEvents | NetworkSignatureInspected |
| Defender For Endpoint/LatestAntivirusScanStatus.md | Defender For Endpoint | DeviceEvents | AntivirusScanCompleted |
| Defender For Endpoint/Living Off The Land/CertutilRemoteDownload.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/Living Off The Land/LOLBinRemoteIPCommandLine.md | Defender For Endpoint | DeviceNetworkEvents |  |
| Defender For Endpoint/Living Off The Land/LOLBinStatistics.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/Living Off The Land/LOLDriverUsage.md | Defender For Endpoint | DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents, externaldata |  |
| Defender For Endpoint/Living Off The Land/LOTSUsage.md | Defender For Endpoint | DeviceNetworkEvents, externaldata |  |
| Defender For Endpoint/Living Off The Land/NewLOLBinExternalConnection.md | Defender For Endpoint | DeviceNetworkEvents |  |
| Defender For Endpoint/Living Off The Land/RMMConnection.md | Defender For Endpoint | DeviceNetworkEvents, externaldata | ConnectionSuccess |
| Defender For Endpoint/LocalAdminAdditions.md | Defender For Endpoint | DeviceEvents | UserAccountAddedToLocalGroup |
| Defender For Endpoint/LocalAdminsWithTheMostDevicesAccessed.md | Defender For Endpoint | DeviceLogonEvents |  |
| Defender For Endpoint/LocalFirewallAdditions.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/LocalFirewallDeletions.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/LocalGroupCreation.md | Defender For Endpoint | DeviceEvents, DeviceInfo, DeviceNetworkEvents | SecurityGroupCreated |
| Defender For Endpoint/LocalGroupDiscovery.md | Defender For Endpoint | DeviceProcessEvents, IdentityInfo |  |
| Defender For Endpoint/MultipleSentitiveGroupAdditions.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/NetDiscoveryActivities.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/NetDiscoveryActivitiesDetected.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/NetQueryStatistics.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/Network - AnyDeskConnectionToPublicIP.md | Defender For Endpoint | DeviceNetworkEvents |  |
| Defender For Endpoint/Network - DevicesWithMostOpenPorts.md | Defender For Endpoint | DeviceNetworkEvents | ListeningConnectionCreated |
| Defender For Endpoint/Network - InterestingOpenPorts.md | Defender For Endpoint | DeviceNetworkEvents | ListeningConnectionCreated |
| Defender For Endpoint/Network - OpenDatabasePorts.md | Defender For Endpoint | DeviceNetworkEvents | ListeningConnectionCreated |
| Defender For Endpoint/Network - OpenRemoteServicePorts.md | Defender For Endpoint | DeviceNetworkEvents | ListeningConnectionCreated |
| Defender For Endpoint/NewRDPConnections.md | Defender For Endpoint | DeviceNetworkEvents | ConnectionSuccess |
| Defender For Endpoint/NewSysinternalToolDetected.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/nf_ttp_generic_kerberos_attacks.md | Defender For Endpoint | AlertInfo, DeviceProcessEvents, IdentityDirectoryEvents | Potential lateral movement path identified |
| Defender For Endpoint/nf_ttp_smoke-sandstorm_unusual_coreuicomponent.dll-behaviour.md | Defender For Endpoint | AlertEvidence, AlertInfo, DeviceImageLoadEvents |  |
| Defender For Endpoint/nf_ttp_t1543_peach-sandstorm_azure_arc_persistence.md | Defender For Endpoint | DeviceEvents, DeviceFileEvents |  |
| Defender For Endpoint/NltestDiscovery.md | Defender For Endpoint | DeviceProcessEvents | ProcessCreated |
| Defender For Endpoint/NTDSDitFileModifications.md | Defender For Endpoint | DeviceFileEvents |  |
| Defender For Endpoint/OutboundConhostConnection.md | Defender For Endpoint | DeviceNetworkEvents |  |
| Defender For Endpoint/PowerShellInvokeWebrequest.md | Defender For Endpoint | DeviceInfo, DeviceNetworkEvents | ConnectionSuccess |
| Defender For Endpoint/PowerShellNoProfile.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/QakbotPostCompromiseCommandsExecuted.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/Ransomware/KillNetRansomwareDetection.md | Defender For Endpoint | DeviceFileEvents |  |
| Defender For Endpoint/Ransomware/RansomwareDoubleExtention.md | Defender For Endpoint | DeviceFileEvents | FileRenamed |
| Defender For Endpoint/Ransomware/RansomwareExtensionFound.md | Defender For Endpoint | DeviceFileEvents, externaldata |  |
| Defender For Endpoint/Ransomware/RansomwareNoteFound.md | Defender For Endpoint | DeviceFileEvents, externaldata |  |
| Defender For Endpoint/Rare_Outgoing_IPv4_Connections.md | Defender For Endpoint | DeviceNetworkEvents | ConnectionSuccess |
| Defender For Endpoint/RareConnectionsMadeByOffice.md | Defender For Endpoint | DeviceRegistryEvents | RegistryValueSet |
| Defender For Endpoint/RareNetParamaterExecutions.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/RemoteSMBConnection.md | Defender For Endpoint | DeviceNetworkEvents | ConnectionSuccess |
| Defender For Endpoint/SliverC2BeaconLoaded.md | Defender For Endpoint | DeviceEvents, DeviceImageLoadEvents, DeviceNetworkEvents | ConnectionSuccess, ImageLoaded, NamedPipeEvent |
| Defender For Endpoint/SmartScreen/SmartScreenEvents.md | Defender For Endpoint | DeviceEvents | SmartScreenUrlWarning |
| Defender For Endpoint/SmartScreen/SmartScreenOverride.md | Defender For Endpoint | DeviceEvents | SmartScreenUserOverride |
| Defender For Endpoint/SMBSessionsByDevice.md | Defender For Endpoint | DeviceNetworkEvents | ConnectionSuccess |
| Defender For Endpoint/SMBSessionsByFileName.md | Defender For Endpoint | DeviceNetworkEvents |  |
| Defender For Endpoint/SuspiciousBrowserChildProcess.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/SuspiciousExplorerChildProcess.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/SuspiciousRUNMRUEntry.md | Defender For Endpoint | DeviceRegistryEvents | RegistryValueSet |
| Defender For Endpoint/ttp_t1027-010_powershellEncodedCommand.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/ttp_t1059-001_powershell_windowsappsdir_fin7.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/ttp_t1127-001_suspNetworkConnMSBuild.md | Defender For Endpoint | DeviceNetworkEvents |  |
| Defender For Endpoint/ttp_t1219_netsupportrat_fin7.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/ttp_t1562-001_disabledefender.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/USB/ConnectedPnPTypes.md | Defender For Endpoint | DeviceEvents | PnpDeviceConnected |
| Defender For Endpoint/USB/USBConnectors.md | Defender For Endpoint | DeviceEvents | PnpDeviceConnected |
| Defender For Endpoint/WebshellDetection.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Endpoint/WevtutilClearLogs.md | Defender For Endpoint | DeviceProcessEvents |  |
| Defender For Identity/AccountWithPasswordNeverExpiresEnabled.md | Defender For Identity | IdentityDirectoryEvents | Account Password Never Expires changed |
| Defender For Identity/AnomalousGroupPolicyDiscovery.md | Defender For Identity | IdentityQueryEvents |  |
| Defender For Identity/AnomalousLDAPTraffic.md | Defender For Identity | DeviceInfo, IdentityQueryEvents | LDAP query |
| Defender For Identity/LastPasswordChange.md | Defender For Identity | IdentityDirectoryEvents | Account Password changed |
| Defender For Identity/NewLateralMovementPathToSensitiveAccountIdentified.md | Defender For Identity | IdentityDirectoryEvents | Potential lateral movement path identified |
| Defender For Identity/PasswordChangeAfterSuccesfulBruteForce.md | Defender For Identity | IdentityDirectoryEvents, IdentityLogonEvents | Account Password changed, LogonFailed, LogonSuccess |
| Defender For Identity/PotentialKerberosEncryptionDowngrade.md | Defender For Identity | IdentityDirectoryEvents | Account Supported Encryption Types changed |
| Defender For Identity/SMBFileCopy.md | Defender For Identity | IdentityDirectoryEvents | SMB file copy |
| Defender For Identity/SuccessfulDeviceCodeAuthentication.md | Defender For Identity | IdentityLogonEvents |  |
| Defender For Identity/UserAddedToSensitiveGroup.md | Defender For Identity | IdentityDirectoryEvents | Group Membership changed |
| Defender For Identity/Visualization - MostInteractiveSignInsByUser.md | Defender For Identity | IdentityLogonEvents |  |
| Defender XDR/AdvancedFeatureDisabled.md | Defender XDR | CloudAppEvents | SetAdvancedFeatures |
| Defender XDR/AlertSupressionAdded.md | Defender XDR | CloudAppEvents | ExclusionConfigurationAdded |
| Defender XDR/CustomDetectionDeletion.md | Defender XDR | CloudAppEvents | DeleteCustomDetection |
| Defender XDR/CustomDetectionDisabled.md | Defender XDR | CloudAppEvents | ChangeCustomDetectionRuleStatus |
| Defender XDR/CustomDetectionReport.md | Defender XDR | CloudAppEvents | CreateCustomDetection, EditCustomDetection |
| Defender XDR/DeviceIsolation.md | Defender XDR | CloudAppEvents | IsolateDevice |
| Defender XDR/DeviceRemovedFromIsolation.md | Defender XDR | CloudAppEvents | IsolateDevice, ReleaseFromIsolation |
| Defender XDR/FileFromHostCollected.md | Defender XDR | CloudAppEvents | DownloadFile, LiveResponseGetFile |
| Defender XDR/LiveResponseFileCollection.md | Defender XDR | CloudAppEvents | LiveResponseGetFile |
| Defender XDR/LiveResponseUnsignedPowerShellChanges.md | Defender XDR | CloudAppEvents | SetAdvancedFeatures |
| Defender XDR/ManualAntivirusScans.md | Defender XDR | CloudAppEvents | RunAntiVirusScan |
| Defender XDR/MDISensorDeleted.md | Defender XDR | CloudAppEvents | SensorDeleted |
| Defender XDR/OffboardingPackageDownloaded.md | Defender XDR | CloudAppEvents | DownloadOffboardingPkg |
| Defender XDR/RBACChanges.md | Defender XDR | CloudAppEvents |  |
| Defender XDR/SentinelWorkspaceDisconnected.md | Defender XDR | CloudAppEvents | SentinelDisconnectWorkspace |
| DFIR/AuditLogs - UserActivities.md | DFIR | AuditLogs |  |
| DFIR/Defender For Endpoint/MDE - AllProcessesCreatedByMaliciousFile.md | DFIR | DeviceFileEvents, DeviceProcessEvents |  |
| DFIR/Defender For Endpoint/MDE - LoadedFiles.md | DFIR | DeviceEvents, DeviceImageLoadEvents, DeviceNetworkEvents, DeviceProcessEvents |  |
| DFIR/Defender For Endpoint/MDE - RemoteImageLoads.md | DFIR | DeviceImageLoadEvents |  |
| DFIR/Entra ID/AuditLogs - UserActivities.md | DFIR | AuditLogs |  |
| DFIR/Entra ID/GraphAPI - SuspiciousUserRequests.md | DFIR | IdentityInfo, MicrosoftGraphActivityLogs |  |
| DFIR/Exposure Management/ExposureManagement - CloudPermissionsUser.md | DFIR | ExposureGraphEdges |  |
| DFIR/Exposure Management/ExposureManagement - DeviceActivities.md | DFIR | ExposureGraphEdges |  |
| DFIR/Exposure Management/ExposureManagement - LateralMovementPaths.md | DFIR | ExposureGraphEdges |  |
| DFIR/ExposureManagement - CloudPermissionsUser.md | DFIR | ExposureGraphEdges |  |
| DFIR/ExposureManagement - DeviceActivities.md | DFIR | ExposureGraphEdges |  |
| DFIR/ExposureManagement - LateralMovementPaths.md | DFIR | ExposureGraphEdges |  |
| DFIR/GraphAPI - SuspiciousUserRequests.md | DFIR | IdentityInfo, MicrosoftGraphActivityLogs |  |
| DFIR/MDCA MDO - MailItemsAccessedByCompromisedAccount.md | DFIR | CloudAppEvents, EmailEvents | MailItemsAccessed |
| DFIR/MDE - AllProcessesCreatedByMaliciousFile.md | DFIR | DeviceFileEvents, DeviceProcessEvents |  |
| DFIR/MDE - ClickFix Triage Query.md | DFIR | DeviceFileEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents, Event | RegistryValueSet |
| DFIR/MDE - LoadedFiles.md | DFIR | DeviceEvents, DeviceImageLoadEvents, DeviceNetworkEvents, DeviceProcessEvents |  |
| DFIR/MDE - Registry-Run-Keys-Forensics.md | DFIR | DeviceRegistryEvents |  |
| DFIR/MDE - RemoteImageLoads.md | DFIR | DeviceImageLoadEvents |  |
| DFIR/XDR - DeviceAlerts.md | DFIR | AlertEvidence, AlertInfo |  |
| DFIR/XDR - UpnAlerts.md | DFIR | AlertEvidence, AlertInfo |  |
| Exposure Management/MostPermissiveEntities.md | Exposure Management | ExposureGraphEdges |  |
| Fun/KQLQueryVisits.md | Fun | DeviceNetworkEvents |  |
| Fun/KQLSearchVisits.md | Fun | DeviceNetworkEvents |  |
| Fun/MailItemsAccessed.md | Fun | CloudAppEvents, OfficeActivity | MailItemsAccessed |
| Fun/TeamsEmojiReactions.md | Fun | CloudAppEvents | ReactedToMessage |
| Fun/TeamsEmojiReactionsByDepartment.md | Fun | CloudAppEvents, IdentityInfo | ReactedToMessage |
| Fun/Visualization - CopilotModelsUsed.md | Fun | CloudAppEvents |  |
| Functions/AnonymizedMicrosoftGraphActivityLogs.md | Functions | MicrosoftGraphActivityLogs |  |
| Functions/AvScanResults.md | Functions | DeviceTvmInfoGathering |  |
| Graph API/AppEnrichmentAADNonInteractiveUserSignInLogs.md | Graph API | AADNonInteractiveUserSignInLogs, MicrosoftGraphActivityLogs |  |
| Graph API/AppEnrichmentExternalData.md | Graph API | MicrosoftGraphActivityLogs, externaldata |  |
| Graph API/AzureHound.md | Graph API | GraphAPIAuditEvents |  |
| Graph API/GraphAPIAuditEvents - AppEnrichmentAADNonInteractiveUserSignInLogs.md | Graph API | AADNonInteractiveUserSignInLogs, GraphAPIAuditEvents |  |
| Graph API/GraphAPIAuditEvents - AppEnrichmentExternalData.md | Graph API | GraphAPIAuditEvents, externaldata |  |
| Graph API/GraphAPIAuditEvents - AzureHound.md | Graph API | GraphAPIAuditEvents |  |
| Graph API/GraphAPIAuditEvents - GraphResourceAPIRequestStats.md | Graph API | GraphAPIAuditEvents |  |
| Graph API/GraphAPIAuditEvents - GraphURIAPIRequestStats.md | Graph API | GraphAPIAuditEvents |  |
| Graph API/GraphAPIAuditEvents - IPEnrichment.md | Graph API | GraphAPIAuditEvents |  |
| Graph API/GraphAPIAuditEvents - UserEnrichment.md | Graph API | GraphAPIAuditEvents, IdentityInfo |  |
| Graph API/GraphResourceAPIRequestStats.md | Graph API | MicrosoftGraphActivityLogs |  |
| Graph API/GraphURIAPIRequestStats.md | Graph API | MicrosoftGraphActivityLogs |  |
| Graph API/IPEnrichment.md | Graph API | MicrosoftGraphActivityLogs |  |
| Graph API/runHuntingQueryExecution.md | Graph API | MicrosoftGraphActivityLogs |  |
| Graph API/runHuntingQueryStatistics.md | Graph API | MicrosoftGraphActivityLogs |  |
| Graph API/UserEnrichment.md | Graph API | IdentityInfo, MicrosoftGraphActivityLogs |  |
| KQL Regex/RegexExamples.md | KQL Regex | DeviceProcessEvents, externaldata |  |
| Learning/TheArtOfKnowingYourData.md | Learning | CloudAppEvents, DeviceEvents, DeviceFileCertificateInfo, DeviceFileEvents, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents |  |
| Log Analytics/LogAnalyticsQueryStatistics.md | Log Analytics | LAQueryLogs |  |
| Office 365/BigYellowTaxi - SignIn.md | Office 365 | AADSignInEventsBeta, CloudAppEvents, OfficeActivity, SigninLogs | MailItemsAccessed |
| Office 365/Email - AIREffectiveness.md | Office 365 | EmailPostDeliveryEvents |  |
| Office 365/Email - MostRareFileExtensionsRecieved.md | Office 365 | EmailAttachmentInfo, EmailEvents |  |
| Office 365/Email - PotentialPhishingCampaign.md | Office 365 | EmailEvents, EmailUrlInfo |  |
| Office 365/Email - SafeLinksTrigger.md | Office 365 | EmailEvents, UrlClickEvents | ClickBlocked |
| Office 365/Email - TyposquattedEmailRecieved.md | Office 365 | EmailEvents |  |
| Office 365/ListSafeLinkEvents.md | Office 365 | UrlClickEvents | ClickBlocked |
| Office 365/Visualization - Email - MalwareDetectionReasons.md | Office 365 | EmailPostDeliveryEvents |  |
| Office 365/Visualization - Email - PhishDetectionReasons.md | Office 365 | EmailPostDeliveryEvents |  |
| Office 365/Visualization - Email - PostDeliveryEvents.md | Office 365 | EmailPostDeliveryEvents |  |
| Security Operations/ComparisonIntuneandMDEDevices.md | Security Operations | DeviceProcessEvents, IntuneDevices |  |
| Security Operations/DevicesCanBeOnboarded.md | Security Operations | DeviceInfo |  |
| Security Operations/IngestionDelays.md | Security Operations | GraphAPIAuditEvents, MicrosoftGraphActivityLogs |  |
| Security Operations/NRT - AutoIRHighImpactAlert.md | Security Operations | AlertEvidence |  |
| Security Operations/OnboardedDeviceByOS.md | Security Operations | DeviceInfo |  |
| Security Operations/SLA - TimeToRespond.md | Security Operations | SecurityIncident |  |
| Security Operations/Statistics - MostTriggeredIncidents.md | Security Operations | AlertInfo, SecurityIncident |  |
| Security Operations/Statistics - MostTriggeredMitreTechniques.md | Security Operations | AlertInfo, SecurityIncident |  |
| Security Operations/TotalEventsByTable.md | Security Operations | — |  |
| Security Operations/Visualization - AntivirusEventsByDay.md | Security Operations | DeviceEvents | AntivirusDetection |
| Security Operations/Visualization - DailyIncidentTriggers.md | Security Operations | AlertInfo, SecurityIncident |  |
| Security Operations/Visualization - DailyTableEvents.md | Security Operations | — |  |
| Security Operations/Visualization - ThreatIntelligenceThreatTypes.md | Security Operations | ThreatIntelligenceIndicator |  |
| Security Operations/XDRAutomaticallyClosedIncidents.md | Security Operations | SecurityIncident |  |
| SecurityEvents/InboundAuthenticationFromPublicIP.md | SecurityEvents | DeviceInfo, SecurityEvent |  |
| SecurityEvents/IngestionSizeSecurityEvents.md | SecurityEvents | SecurityEvent |  |
| SecurityEvents/ListADDelegations.md | SecurityEvents | SecurityEvent |  |
| SecurityEvents/NltestDiscovery.md | SecurityEvents | SecurityEvent |  |
| SecurityEvents/UserAccountDeletion.md | SecurityEvents | SecurityEvent |  |
| Sentinel/AnalyticsRulesEfficiency.md | Sentinel | SecurityIncident |  |
| Sentinel/LargeNumberOfAnalyticsRulesDeleted.md | Sentinel | AzureActivity |  |
| Sentinel/ListGlobalAdmins.md | Sentinel | IdentityInfo |  |
| Sentinel/SentinelAnomalies.md | Sentinel | Anomalies |  |
| Sentinel/Summary Rules/EntraGroupMembershipReport.md | Sentinel | IdentityInfo |  |
| Sentinel/Summary Rules/EntraRolesReport.md | Sentinel | IdentityInfo |  |
| Sentinel/Summary Rules/UniqueActions.md | Sentinel | — |  |
| Sentinel/Visualization - IncidentsTriggeredByMitreTactic.md | Sentinel | SecurityIncident |  |
| Sentinel/Visualization - IncidentsTriggeredByMitreTechniques.md | Sentinel | SecurityIncident |  |
| Sentinel/Visualization - ThreatIntelligenceIndicatorTriggered.md | Sentinel | ThreatIntelligenceIndicator |  |
| Sentinel/Visualization - ThreatIntelligenceIndicatorTriggeredByDay.md | Sentinel | ThreatIntelligenceIndicator |  |
| Threat Hunting/Behavior - AsyncRATInitialAccess.md | Threat Hunting | DeviceFileEvents, EmailAttachmentInfo, EmailEvents |  |
| Threat Hunting/Behavior - InboundConnectionFromMaliciousIP.md | Threat Hunting | DeviceInfo, DeviceNetworkEvents, externaldata | InboundConnectionAccepted |
| Threat Hunting/Behavior - TelegramC2.md | Threat Hunting | DeviceNetworkEvents |  |
| Threat Hunting/Behaviour - APT28Commands.md | Threat Hunting | DeviceProcessEvents |  |
| Threat Hunting/Behaviour - APT28ExternalWebdav.md | Threat Hunting | DeviceProcessEvents |  |
| Threat Hunting/Behaviour - KillSQLProcesses.md | Threat Hunting | DeviceProcessEvents |  |
| Threat Hunting/Behaviour - SuspiciousNamedPipes.md | Threat Hunting | DeviceEvents, externaldata | NamedPipeEvent |
| Threat Hunting/IOC - BlackCatRansomware.md | Threat Hunting | DeviceFileEvents, DeviceNetworkEvents |  |
| Threat Hunting/IOC - CiscoYanluowangRansomware.md | Threat Hunting | DeviceFileEvents, DeviceNetworkEvents |  |
| Threat Hunting/IOC - NighthawkRat.md | Threat Hunting | DeviceFileEvents |  |
| Threat Hunting/Ransomware - APTNotesJoinTable.md | Threat Hunting | externaldata |  |
| Threat Hunting/Ransomware - APTNotesSHA1IOC.md | Threat Hunting | DeviceFileEvents, externaldata |  |
| Threat Hunting/Ransomware - LeaksiteMontitoring.md | Threat Hunting | externaldata |  |
| Threat Hunting/STORM-0539 URLPathsEmail.md | Threat Hunting | EmailEvents, EmailUrlInfo |  |
| Threat Hunting/TI Feed - 2022-TalosEmotetDomain.md | Threat Hunting | DeviceNetworkEvents, externaldata |  |
| Threat Hunting/TI Feed - 2022-TalosEmotetSHA256.md | Threat Hunting | DeviceFileEvents, externaldata |  |
| Threat Hunting/TI Feed - DigitalSideDomains.md | Threat Hunting | DeviceNetworkEvents, externaldata |  |
| Threat Hunting/TI Feed - DigitalSideIPs.md | Threat Hunting | DeviceNetworkEvents, externaldata |  |
| Threat Hunting/TI Feed - ipfs_phishing.md | Threat Hunting | DeviceNetworkEvents, EmailEvents, EmailUrlInfo, externaldata |  |
| Threat Hunting/TI Feed - JA3Blacklist.md | Threat Hunting | DeviceNetworkEvents, externaldata |  |
| Threat Hunting/TI Feed - ThreatviewioDomain-High-Confidence-Feed.md | Threat Hunting | DeviceNetworkEvents, externaldata |  |
| Threat Hunting/TI Feed - ThreatviewioIP-High-Confidence-Feed.md | Threat Hunting | DeviceNetworkEvents, externaldata |  |
| Threat Hunting/TI Feed - TorConnections.md | Threat Hunting | DeviceNetworkEvents, externaldata | ConnectionSuccess |
| Vulnerability Exploitation/CVE-2024-49113 - LDAPNightmare.md | Vulnerability Exploitation | DeviceNetworkEvents | InboundConnectionAccepted |
| Vulnerability Exploitation/Follina.md | Vulnerability Exploitation | DeviceNetworkEvents, DeviceProcessEvents | ConnectionSuccess |
| Vulnerability Exploitation/MS Exchange Zero Day Sept 2022.md | Vulnerability Exploitation | DeviceFileEvents, DeviceNetworkEvents |  |
| Vulnerability Management/Active-EOS-Software.md | Vulnerability Management | DeviceTvmSoftwareInventory |  |
| Vulnerability Management/DueDatePassedCISAKnownExploitedVulnerability.md | Vulnerability Management | DeviceTvmSoftwareVulnerabilities, externaldata |  |
| Vulnerability Management/InboundSSHConnectionToVulnerableXZMachine.md | Vulnerability Management | DeviceNetworkEvents, DeviceTvmSoftwareInventory | InboundConnectionAccepted |
| Vulnerability Management/NewActiveCISAKnownExploitedVulnerabilityDetected.md | Vulnerability Management | DeviceProcessEvents, DeviceTvmSoftwareVulnerabilities, externaldata |  |
| Vulnerability Management/PrioritizeSecureConfiguration.md | Vulnerability Management | DeviceTvmSecureConfigurationAssessment, DeviceTvmSecureConfigurationAssessmentKB |  |
| Vulnerability Management/SentinelAnalyticsRuleNewCISAKnowExploitedVulnerabilityAdded.md | Vulnerability Management | SecurityIncident, externaldata |  |
| Vulnerability Management/Top-Devices-Most-Exploitable-Vulnerabilities.md | Vulnerability Management | DeviceTvmSoftwareVulnerabilities, DeviceTvmSoftwareVulnerabilitiesKB |  |
| Vulnerability Management/Visualization - ActiveCISAKEV.md | Vulnerability Management | DeviceTvmSoftwareVulnerabilities, externaldata |  |
| Vulnerability Management/Visualization - ExposureLevels.md | Vulnerability Management | DeviceInfo |  |
| Vulnerability Management/Visualization - VulnerabilitiesBySeverity.md | Vulnerability Management | DeviceTvmSoftwareVulnerabilities |  |
