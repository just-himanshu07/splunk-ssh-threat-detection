# SSH Authentication Log Analysis & Threat Detection Using Splunk

**Project Type:** Cybersecurity | SIEM | SOC Analyst Lab  
**Tools:** Splunk Enterprise, SPL, JSON Logs  
**Focus Areas:** Log Analysis, Authentication Monitoring, Threat Detection

---

## 1. Project Overview

This project focuses on analyzing SSH authentication logs using Splunk Enterprise to identify suspicious login activity and investigate potential brute-force attempts.

The project uses JSON-formatted, Zeek-style SSH logs to simulate a security monitoring workflow commonly performed by a Security Operations Center (SOC) Analyst.

By using Splunk Search Processing Language (SPL), the logs are analyzed to identify failed authentication attempts, successful logins, suspicious source IP addresses, and unusual authentication patterns.

## 2. Project Objectives

- Ingest and analyze SSH authentication logs in Splunk.
- Identify failed and successful authentication events.
- Detect source IP addresses generating repeated failed login attempts.
- Analyze event types and authentication patterns.
- Investigate potential brute-force activity.
- Practice SPL queries used in SOC investigations.

## 3. Tools & Technologies

| Tool | Purpose |
|---|---|
| Splunk Enterprise 9.3.0 | Log analysis and security monitoring |
| SPL | Searching and investigating events |
| JSON | SSH log data format |
| Zeek-style logs | Network connection and SSH event data |

## 4. Project Architecture

```text
SSH Log Dataset (JSON)
          |
          v
    Splunk Ingestion
          |
          v
    Event Field Extraction
          |
          v
       SPL Queries
          |
          v
  Authentication Analysis
          |
          v
 Suspicious IP Identification
          |
          v
  SOC Investigation & Findings
```

## 5. Dataset

**Source:** [SSH Log Dataset – GitHub](https://raw.githubusercontent.com/0xrajneesh/30-Days-SOC-Challenge-Beginner/refs/heads/main/ssh_logs.json)

The dataset contains SSH-related fields such as:

- `auth_success` — authentication success indicator
- `auth_attempts` — authentication attempt count
- `event_type` — event classification
- `id.orig_h` — source IP address
- `id.resp_h` — destination IP address
- `id.resp_p` — destination port
- `conn_state` — connection state

## 6. Implementation & Investigation

### Investigation 1: Identify Top Source IPs with Failed Authentication

**Objective:** Identify the source IP addresses responsible for the highest number of failed authentication events.

```spl
index=ssh_logs sourcetype="_json" auth_success=false
| stats count by id.orig_h
| sort -count
| head 10
```

**Investigation points:**
- Identify the source IP with the highest event count.
- Compare the number of failed events across source IPs.
- Investigate repeated failures for potential brute-force behavior.

### Investigation 2: Calculate Total SSH Events

**Objective:** Establish the total number of indexed SSH events.

```spl
index=ssh_logs sourcetype="_json"
| stats count as total_ssh_events
```

This provides an overview of the dataset available for investigation.

**Note:** The result represents indexed events, not necessarily unique SSH sessions.

### Investigation 3: Analyze SSH Event Distribution

**Objective:** Understand which SSH event categories appear most frequently.

```spl
index=ssh_logs sourcetype="_json"
| stats count by event_type
| sort -count
```

This query helps compare failed login events, multiple failed authentication events, and successful login events where present.

### Investigation 4: Investigate Successful Authentication

**Objective:** Identify source IP addresses associated with successful authentication events.

```spl
index=ssh_logs sourcetype="_json" auth_success=true
| stats count by id.orig_h
| sort -count
| head 10
```

Compare these results with failed authentication activity to identify sources that may require closer investigation.

### Investigation 5: Review Failed Authentication Details

**Objective:** Inspect individual failed authentication events.

```spl
index=ssh_logs sourcetype="_json" auth_success=false
| table _time id.orig_h id.resp_h id.resp_p auth_attempts event_type
```

Review the timestamps, source IPs, destination IPs, destination ports, and authentication attempt counts.

## 7. Initial Findings

Based on the analysis performed in the lab:

- **608 events** were returned by the failed-authentication filter.
- **305 events** were categorized as `Failed SSH Login`.
- **303 events** were categorized as `Multiple Failed Authentication Attempts`.
- Source IP analysis identified hosts generating repeated failed authentication events.

These are dataset-specific results, not universal findings. Repeated failed logins may indicate brute-force activity, but additional evidence is required to confirm an attack or successful compromise.

## 8. Evidence & Screenshots

Store your investigation screenshots in the following directory:

```text
screenshots/
├── failed-login-sources.png
├── total-ssh-events.png
├── event-type-analysis.png
├── successful-logins.png
└── failed-login-details.png
```

Add your actual screenshots to the repository and display them in this section.

Example:

```markdown
### Failed SSH Login Source Analysis

![Failed SSH Login Sources](screenshots/failed-login-sources.png)
```

## 9. Skills Demonstrated

- SIEM log analysis using Splunk
- SPL search and aggregation
- SSH authentication monitoring
- Source IP investigation
- Initial brute-force detection
- Security event triage
- Evidence-based investigation

## 10. Conclusion

This project demonstrates how Splunk can be used to investigate SSH authentication activity, identify repeated failed login events, and prioritize suspicious source IP addresses for further analysis.

It provides practical experience with SIEM-based investigations and the initial triage process used by SOC Analysts.

**Future Improvements:**
- Build a dashboard for SSH authentication activity.
- Create alerts for repeated failed login attempts.
- Add time-based detection to identify bursts of authentication failures.
- Correlate failed and successful logins from the same source IP.
- Enrich suspicious IPs with trusted threat intelligence sources.

---

**Disclaimer:** This project uses a lab dataset for educational purposes. Findings should be validated before treating any activity as a confirmed security incident.
