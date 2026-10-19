# Project: SSH Authentication Log Analysis & Threat Detection
## Tool: Splunk Enterprise
## Dataset: Zeek-style SSH JSON logs


# 1. Top 10 Source IPs with Failed SSH Logins

index=ssh_logs sourcetype="_json" auth_success=false
| stats count by id.orig_h
| sort -count
| head 10


# 2. Total SSH Events

index=ssh_logs sourcetype="_json"
| stats count as total_ssh_events


# 3. SSH Events by Event Type

index=ssh_logs sourcetype="_json"
| stats count by event_type
| sort -count


# 4. Top Source IPs with Successful SSH Logins

index=ssh_logs sourcetype="_json" auth_success=true
| stats count by id.orig_h
| sort -count
| head 10


# 5. Detailed Failed Authentication Events

index=ssh_logs sourcetype="_json" auth_success=false
| table _time id.orig_h id.resp_h id.resp_p auth_attempts event_type


# 6. Failed Authentication Activity Over Time

index=ssh_logs sourcetype="_json" auth_success=false
| timechart span=5m count as failed_attempts


# 7. Source IPs with High Failed Login Counts

index=ssh_logs sourcetype="_json" auth_success=false
| stats count as failed_attempts by id.orig_h
| where failed_attempts >= 10
| sort -failed_attempts


# 8. Compare Successful and Failed Authentication Events

index=ssh_logs sourcetype="_json"
| stats count(eval(auth_success=true)) as successful_logins
        count(eval(auth_success=false)) as failed_logins


# 9. Investigate Sources with Both Failed and Successful Events

index=ssh_logs sourcetype="_json"
| stats count(eval(auth_success=false)) as failed_logins
        count(eval(auth_success=true)) as successful_logins
        by id.orig_h
| where failed_logins > 0 AND successful_logins > 0
| sort -failed_logins


# 10. Review SSH Destination Ports

index=ssh_logs sourcetype="_json"
| stats count by id.resp_p
| sort -count
