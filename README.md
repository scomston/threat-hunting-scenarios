# Threat Hunting Scenarios - Devices Exposed to the Internet

## Scenario

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

---

# Timeline Summary and Findings

## Internet Exposure

`windows-target-1` has been internet-facing for several days.

```kusto
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
```
Last internet-facing time: 2025-06-04T20:55:38.3212862Z

## Brute Force Login Attempts
Several bad actors attempted to log into the target machine.

```kusto
DeviceLogonEvents
| where DeviceName == "shawn-mde-test"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

## Failed Logons - Top IPs
The top 5 IPs with failed login attempts did not succeed in accessing the VM.
```kusto
let RemoteIPsInQuestion = dynamic([
  "119.42.115.235","183.81.169.238", "74.39.190.50",
  "121.30.214.172", "83.222.191.62", "45.41.204.12", "192.109.240.116"
]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

Query Result: No successful logons from these IPs.

## Valid Account Logons
The only successful remote/network logons in the last 30 days were for the 'labuser' account (2 total).

```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count()
```

There were zero (0) failed logons for the 'labuser' account, indicating no brute force attempts occurred for it.
```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize count()
```

## IP Address Review for 'labuser'
Checked all successful login IPs for 'labuser' — all were expected and normal.
```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```
## Summary
Although the device was exposed to the internet and brute force attempts occurred, no evidence suggests that these were successful or that 'labuser' was compromised.

## Relevant MITRE ATT&CK TTPs
### MITRE ATT&CK TTPs Observed
TA0001: Initial Access

T1133: External Remote Services
Brute force attempts against exposed RDP/Network services.

TA0006: Credential Access

T1110: Brute Force
Multiple failed logon attempts from various IPs (no success).

TA0007: Discovery (Implied potential intent)
No evidence of successful discovery, but behavior suggests probing for valid credentials or accounts.

### Not Observed (But Often Related)
T1078: Valid Accounts
Not applicable here, as 'labuser' was not accessed by unauthorized users.

TA0005: Defense Evasion
No indicators of log tampering or evasion tactics.

## Response Actions
Hardened the NSG attached to windows-target-1 to allow only RDP traffic from specific endpoints (no public internet access)

Implemented account lockout policy

Implemented MFA







