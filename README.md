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

49️⃣ Procdump Execution
Spl
Copy code
index=botsv3 EventCode=4688 New_Process_Name="*procdump.exe*"
50️⃣ Mimikatz Indicator
Spl
Copy code
index=botsv3 Command_Line="*mimikatz*"

---

## 🎯 **Use Case: Detecting LaZagne Execution**

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


