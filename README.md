# 🔥 Splunk SOC Lab – Detection Engineering Project

This project simulates a real-world **Blue Team / SOC Investigation** using **BOTS v3 dataset**

The objective was to **analyze attacker** activity across the environment, **build detection use cases**, map them to **MITRE ATT&CK**, and **create alerts** and **dashboards** as if operating in a production SOC.
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
The lab includes:

- Log analysis
- Threat hunting
- SPL detection engineering
- Alert configuration
- MITRE ATT&CK mapping
- Security impact documentation
- Incident response guidance
- Dashboard development

All execution evidence (screenshots) is stored in:
`/evidence/`

---

## 🚀 **Project Architecture**

![Architecture Diagram](ev0.jpg)

🏗️ **Environment**

- SIEM: Splunk Enterprise
- Dataset: BOTS v3
- Log Sources:
  - Windows Security Logs
  - Sysmon
  - DNS Logs
  - Web Logs
  - Endpoint Logs

---

## 🧠 **Technology Stack**



## 1️⃣ Brute Force – Single Account


```bash

index=botsv3 EventCode=4625 earliest=-5m
| stats count by Account_Name src_ip
| where count > 15 

```
## 2️⃣ Password Spray (Single IP → Many Accounts)


```bash

index=botsv3 EventCode=4625 earliest=-5m
| stats dc(Account_Name) as unique_users count by src_ip
| where unique_users > 15

```
## 3️⃣ Brute Force Followed by Success


```bash

index=botsv3 (EventCode=4625 OR EventCode=4624) earliest=-10m
| stats 
    count(eval(EventCode=4625)) as failures
    count(eval(EventCode=4624)) as success
    by Account_Name src_ip
| where failures > 10 AND success > 0

```
## 4️⃣ Account Lockout Spike


```bash

index=botsv3 EventCode=4740 earliest=-10m
| stats count by Account_Name
| where count > 3

```
## 5️⃣ User Added to Local Admin Group


```bash

index=botsv3 EventCode=4732
| search Group_Name="*Administrators*"

```

## 6️⃣ Domain Admin Group Modification


```bash

index=botsv3 EventCode=4728
| search Group_Name="*Domain Admins*"

```

## 8️⃣ Special Privileges Assigned (4672)

```bash

index=botsv3 EventCode=4672
| search Account_Name!="SYSTEM"

```
## 9️⃣ New Account Creation

```bash

index=botsv3 EventCode=4720

```
## 🔟 Service Installation

```bash

index=botsv3 EventCode=7045

```
## 1️⃣1️⃣ Scheduled Task Creation

```bash

index=botsv3 EventCode=7045

```

## 1️⃣2️⃣ RDP Logon Spike



## 1️⃣3️⃣ Lateral Movement


```bash

index=botsv3 EventCode=4624 Logon_Type=3
| stats dc(ComputerName) as hosts by Account_Name
| where hosts > 4

```
## 1️⃣4️⃣ DNS High Volume

```bash

index=botsv3 sourcetype=stream:dns earliest=-5m
| stats count by src_ip
| where count > 300

```
## 1️⃣5️⃣ Rare Domain Contact

```bash

index=botsv3 sourcetype=stream:dns
| stats count by query
| where count < 5

```
## 1️⃣6️⃣ NTLM Spike Attempts 

```bash

index=botsv3 EventCode=4776 earliest=-5m
| stats count dc(Account_Name) as users by src_ip
| where count > 30 AND users > 10

```
## 1️⃣7️⃣ Multiple IP Login Per Account 

```bash

index=botsv3 EventCode=4624 earliest=-24h
| stats dc(src_ip) as ips by Account_Name
| where ips > 5

```



















1️⃣5️⃣
1️⃣6️⃣
1️⃣7️⃣
1️⃣8️⃣
1️⃣9️⃣
2️⃣0️⃣


















---

## 🎯 **Use Case: Detecting LaZagne Execution**

Domain Admin Group Modification

The detection rule identifies:

* Process name & file path containing `LaZagne`
* Command line arguments
* OS being Windows

Once detected → event is immediately sent to **Tines**.

### 📌 LimaCharlie Detection Rule (YAML)

```yaml\ nop: and
events:
  - NEW_PROCESS
rules:
  - op: contains
    path: event/FILE_PATH
    value: LaZagne
  - op: contains
    path: event/COMMAND_LINE
    value: LaZagne
  - op: is
    path: event/OS
    value: windows
```

---

## 📡 **Slack Alerting**

Tines parses the incoming LC event and sends a structured alert to Slack including:

* Time of detection
* Hostname
* Local/External IP
* Executed file
* Command line used
* Link to detection in LimaCharlie

![Slack Alert](evidence/ev3.png)

---

## 🧩 **Tines Story Workflow**

This story performs:

1. Receive webhook from LC
2. Parse detection fields
3. Send alert to Slack
4. Prompt analyst for YES/NO isolation
5. If YES → isolate via LC API
6. If NO → notify Slack & close case

![Tines Workflow](evidence/ev1.png)

The automated analyst prompt:

![Prompt](evidence/ev2.png)

---

## 🛡 **Host Isolation Logic**

If analyst selects **YES** →

* Tines triggers LimaCharlie API
* Endpoint is isolated
* Slack receives confirmation message

If **NO** →

* Tines informs that machine was NOT isolated and requires investigation

---

## 🔍 **LimaCharlie Detection Evidence**

Screenshot from LC showing detection details:

![Detection](evidence/ev4.png)

Timeline of events during LaZagne execution:

![Timeline](evidence/ev5.png)

---

## 🖥 **LimaCharlie Agent Installed Successfully**

![Agent Install](evidence/ev7.png)

---

## 🧪 **Webhook Testing in Tines**

![Webhook Test](evidence/ev6.png)

---

## 🏆 **Project Outcomes**

This project demonstrates:

* ✔ Real SOC automation experience
* ✔ EDR detection engineering
* ✔ SOAR automation building
* ✔ Incident response workflow design
* ✔ Practical Slack integration
* ✔ Host isolation using API
* ✔ End‑to‑end attack simulation handling

This is the exact type of project security analysts, DFIR engineers, and SOC developers build inside real enterprises.

---

## 🌍 **How to Use This Repository**

**1. Clone the repo**

```bash
git clone <your-repo-url>
```

**2. Explore folders**

* `/evidence` → All screenshots
* `/rules` → LimaCharlie detection rules
* `/tines-story` → Exported Tines JSON
* `README.md` → Documentation

**3. Review detection logic**
**4. Review SOAR workflow**
**5. Rebuild your own pipeline using these steps**

---


