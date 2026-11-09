# Security Investigation 004 — Suspicious Administrator Login

> **SIMULATED SOC CASE STUDY — NOT A REAL INCIDENT**
>
> All timestamps, hosts, event relationships, confirmation from an account owner, and IP addresses in this report are fictional training data. The investigation conclusion applies **only** to the stated simulation assumptions. No live Windows logs or real organizational records were examined.

## Case Metadata

- **Case ID:** SOC-004
- **Scenario:** Failed administrator logins followed by successful login and system reconnaissance
- **Target host:** `WIN-SRV01` (fictional)
- **Account:** `admin` (fictional)
- **Source IP:** `203.0.113.45` (documentation-only address, not a real attacker attribution)
- **Assessment:** Confirmed unauthorized access **within the simulated case**, based on the supplementary assumptions below
- **Data source:** Instructor-created CSV examples of Windows Security event IDs; not native EVTX files

## Initial Alert

Five failed login attempts (Windows Security Event ID 4625) targeting `admin` occurred between 10:15:01 and 10:15:13. A successful login (Event ID 4624) was recorded at 10:15:18.

This sequence is **suspicious**, but not proof of account compromise by itself.

## Simulated Event Timeline

| Time | Event | Interpretation |
|---|---|---|
| 10:15:01–10:15:13 | Five 4625 events | Failed login attempts |
| 10:15:18 | 4624, Logon ID `0x72A91` | Successful login; requires user verification |
| 10:15:25 | 4688 `explorer.exe` | Process creation |
| 10:15:32 | 4688 `cmd.exe` | Command shell launched |
| 10:15:40 | 4688 `whoami.exe` | User discovery |
| 10:15:47 | 4688 `ipconfig.exe /all` | Network configuration discovery |
| 10:15:55 | 4688 `powershell.exe -NoProfile -Command "Get-LocalUser"` | Local account discovery |
| 10:16:20 | 4634 | Logoff event |

## Correlation and Verification

The base CSV files show **times, usernames, and process names**, but they do not contain all the fields needed to attribute every process to the successful login. In a real investigation, correlate:

1. Security events 4624, 4625 and 4634 with **Logon ID**, Logon Type, source address and host.
2. Event 4688 process creation data with **Process ID, creator/parent Process ID, user context**, command line (if enabled), and process/session telemetry (e.g., Sysmon or EDR).
3. Account owner verification, approved change tickets, scheduled maintenance and expected administrator activity.

**Additional fictional assumptions used to close this scenario:**
- Enhanced endpoint telemetry correlates the listed commands to the same suspicious logon session.
- The legitimate account owner confirms they did not perform the login.
- No authorized maintenance or approved remote administration matches the source or time.

## Decision

**Confirmed unauthorized account access in this simulated scenario**, assuming the additional verification statements are true.

**Not established:** Malware execution, persistence, lateral movement or data exfiltration. The commands shown alone do not prove any of these outcomes.

## Recommended SOC Response

1. Escalate to the incident response lead; preserve relevant event logs and endpoint evidence.
2. Follow the approved response playbook to contain the affected account/session and review other sessions.
3. Reset credentials and revoke active tokens **after coordination with the account owner and IR team**; review MFA and suspicious sign-in sources.
4. Scope additional logins, process execution, network connections and possible persistence or data access.
5. Document findings, confidence level, evidence gaps and recovery actions.

## Practical Learning

- 4625 = failed logon; 4624 = successful logon; 4688 = process creation (when auditing is enabled).
- A successful login after failures increases suspicion, not certainty.
- Discovery commands such as `whoami`, `ipconfig`, and `Get-LocalUser` need context.
- Correlation and user/authorization validation determine whether an alert becomes a confirmed incident.

## Evidence Limitations

The training CSV files are simplified representations, not complete Windows EVTX records. Actual Event ID 4688 schemas and captured fields depend on Windows audit policy; do not assume every 4688 event independently contains a Logon ID suitable for matching. The specific source IP used is reserved for documentation (RFC 5737).

## Ethics

No unauthorized systems were targeted. This write-up describes a closed, invented training scenario.
