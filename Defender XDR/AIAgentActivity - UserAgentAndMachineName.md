# AI Agent Activity - User Agent and Machine Name

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1526 | Cloud Service Discovery | https://attack.mitre.org/techniques/T1526/ |

#### Description
This detection pivots Microsoft Defender AI-agent runtime activity (`CloudAppEvents`) against the `AgentsInfo` inventory and `DeviceInfo`, so that each row shows which agent acted, from which user agent, and on which machine (device). `AgentsInfo` provides the current state of each agent (resolved with `arg_max`), `CloudAppEvents` provides the runtime activity, and `DeviceInfo` is used to recover the machine name.

Note that the IP-to-`PublicIP` join is best-effort: it relies on the agent activity IP matching a known device public IP, and can be swapped to `AadDeviceId` if your connector emits it. The query also requires the Microsoft 365 app connector / Agent 365 observability to be enabled, otherwise `CloudAppEvents` returns no agent rows.

#### Risk
AI agents that can reach cloud services on behalf of users expand the attack surface: a compromised or misconfigured agent may enumerate or act against cloud resources. Correlating agent activity with the originating user agent and machine name helps analysts attribute the activity and spot agents running from unexpected devices or clients.

#### References
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview

## Defender XDR
```KQL
// AI agent runtime activity enriched with the user-agent string and the machine (device) name.
// AgentsInfo = agent inventory (current state via arg_max). CloudAppEvents = agent runtime activity.
let AgentInventory =
    AgentsInfo
    | summarize arg_max(Timestamp, *) by AgentId
    | where LifecycleStatus != "Deleted"
    | mv-expand Endpoint = Endpoints to typeof(string)
    | project AgentId, AgentName, Platform, Model, Owners, Endpoint;
let DeviceNames =
    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    | project DeviceId, DeviceName, PublicIP, OSPlatform;
CloudAppEvents
| where Application in ("Agent 365", "Microsoft 365 Copilot") or ActionType has "Agent"
| where isnotempty(UserAgent)
| extend AgentId = tostring(parse_json(RawEventData).AgentId)
| join kind=leftouter AgentInventory on AgentId
// IP-based join to recover the machine name; swap to AadDeviceId if your connector emits it.
| join kind=leftouter DeviceNames on $left.IPAddress == $right.PublicIP
| project
    Timestamp,
    AgentName,
    AgentId,
    Platform,
    Model,
    Owners,
    AccountDisplayName,
    UserAgent,            // user agent
    DeviceName,           // machine name
    Endpoint,             // where the agent runs (from AgentsInfo)
    IPAddress,
    ActionType,
    ReportId
| sort by Timestamp desc
```

## Sentinel
```KQL
// AI agent runtime activity enriched with the user-agent string and the machine (device) name.
// AgentsInfo = agent inventory (current state via arg_max). CloudAppEvents = agent runtime activity.
let AgentInventory =
    AgentsInfo
    | summarize arg_max(Timestamp, *) by AgentId
    | where LifecycleStatus != "Deleted"
    | mv-expand Endpoint = Endpoints to typeof(string)
    | project AgentId, AgentName, Platform, Model, Owners, Endpoint;
let DeviceNames =
    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    | project DeviceId, DeviceName, PublicIP, OSPlatform;
CloudAppEvents
| where Application in ("Agent 365", "Microsoft 365 Copilot") or ActionType has "Agent"
| where isnotempty(UserAgent)
| extend AgentId = tostring(parse_json(RawEventData).AgentId)
| join kind=leftouter AgentInventory on AgentId
// IP-based join to recover the machine name; swap to AadDeviceId if your connector emits it.
| join kind=leftouter DeviceNames on $left.IPAddress == $right.PublicIP
| project
    TimeGenerated,
    AgentName,
    AgentId,
    Platform,
    Model,
    Owners,
    AccountDisplayName,
    UserAgent,            // user agent
    DeviceName,           // machine name
    Endpoint,             // where the agent runs (from AgentsInfo)
    IPAddress,
    ActionType,
    ReportId
| sort by TimeGenerated desc
```
