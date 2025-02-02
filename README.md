
# Building a SOC + Honeynet in Azure (Live Traffic)
![image](https://github.com/user-attachments/assets/57068781-2b92-4fcf-bd31-da4e0b179d6b)

## Introduction

In this project, I build a mini honeynet in Azure and ingest logs from various resources into a Log Analytics Workspace, which is then used by Microsoft Sentinel to build attack maps, trigger alerts, and create incidents. I measured some security metrics in the insecure environment for 24 hours, applied security controls to harden the environment, measured metrics for another 24 hours, and then shared the results below. The metrics we will collect are:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)

The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Storage Account
- Microsoft Sentinel


## Attack Maps Before Hardening / Security Controls
![image](https://github.com/user-attachments/assets/04d8f1a2-0aa4-4dde-ba94-5f51a28f8956)
<br><br>
![image](https://github.com/user-attachments/assets/f673e734-5dea-4e6f-80fa-f7e70b101750)
<br><br>
![image](https://github.com/user-attachments/assets/44be774c-ff93-4f96-beb6-294f928eba94)
<br><br>
![image](https://github.com/user-attachments/assets/bc99de56-89f0-4923-9757-65dc3fc2726a)
<br><br>

## Attack Maps After Hardening / Security Controls
```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Summary

In this project, a mini honeynet was constructed in Microsoft Azure and the logs were pushed into a Log Analytics Workspace for analysis. Microsoft Sentinel was employed to trigger alerts and create incidents based on the ingested logs. Additionally, metrics were measured in the insecure environment before security controls were applied, and then again after implementing security measures. No security alarms were triggered after the security controls were applied, demonstrating their effectiveness.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.


## KQL Queries

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Start/Stop Time                              | range x from 1 to 1 step 1<br>\| project StartTime = ago(24h), StopTime = now()                                                                  |
| Security Events (Windows VMs)                | SecurityEvent<br>\| where TimeGenerated>= ago(24h)<br>\| count                                                                                   |
| Syslog (Linux VMs)                           | Syslog<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                                         |
| SecurityAlert (Microsoft Defender for Cloud) | Security Alert<br>\| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"<br>\| where TimeGenerated >= ago(24h)<br>\| count |
| Security Incident (Sentinel Incidents)       | SecurityIncident<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                               |
| NSG Inbound Malicious Flows Allowed          | AzureNetworkAnalytics_CL<br>\| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0<br>\| where TimeGenerated >= ago(24h)<br>\| count    |
