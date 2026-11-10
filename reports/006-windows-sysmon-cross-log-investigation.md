# SOC-006 — Windows Security and Sysmon Cross-Log Investigation

> **Authorized training sample analysis.** This case analyzes two publicly available EVTX samples from Yamato Security. It does **not** establish that the sample's named Zerologon activity actually occurred, and it is not a live production incident.

## Executive Summary

A Kali Linux investigation used Hayabusa 4.3.1 to parse two training EVTX files from the [Hayabusa sample EVTX collection](https://github.com/Yamato-Security/hayabusa-sample-evtx):

- `YamatoSecurity/LateralMovement/T1210_Zerologon_WindowsDefaultLogging.evtx`
- `YamatoSecurity/LateralMovement/T1210_Zerologon_Sysmon.evtx`

The combined detection timeline contained **28 detection rows**, with process creation/termination records, Kerberos ticket requests, Sysmon configuration/service events, and a **Windows Security 1102 log-clearing event**. An administrator-associated logon session (`0x67589`) appeared in the 1102 record and three Sysmon process-creation detections. This supports **cross-log session correlation**, but it does **not** identify the actual process or individual who cleared the log.

**Disposition:** Security log clearing confirmed in training evidence; suspicious and deserving follow-up. Zerologon exploitation, account compromise, and deliberate defense evasion **not proven**.

## Evidence Sources and Limits

- Tool: Hayabusa 4.3.1 (`dfir-timeline`) on Kali Linux.
- Input: two **training** EVTX sample files, not live enterprise telemetry.
- Output analyzed: `case-006-timeline.csv` (Hayabusa detection results).
- The 28 entries are **detection rows**, not necessarily 28 unique Windows event records or the complete raw EVTX content.
- All timestamps below are retained in the original `-05:00` offset.
- The analyst did not independently verify native XML for these two files, collect packet captures, or validate business authorization.

## Detection Summary

| Event ID | Detection rows | Observed rule |
|---|---:|---|
| Sysmon 1 | 11 | 10 Proc Exec; 1 Elevated System Shell Spawned |
| Sysmon 5 | 10 | Proc Terminated |
| Security 4769 | 4 | Kerberos Service Ticket Requested |
| Sysmon 16 | 1 | Sysmon Config Change |
| Sysmon 4 | 1 | Sysmon Service State Changed |
| Security 1102 | 1 | Log Cleared |
| **Total** | **28** | **7 rule titles** |

**Deduplication note:** At 04:43:46.320, a single process execution appears in both `Proc Exec` and `Elevated System Shell Spawned` results. Distinct detection rows do not automatically mean distinct host events.

## Evidence-Based Timeline

| Timestamp (2022-02-23, -05:00) | Evidence | Assessment |
|---|---|---|
| 04:37:18.799 | Sysmon event 16: config string includes `Sysmon64.exe -accepteula -i` | Consistent with Sysmon setup/configuration |
| 04:37:18.848 | Sysmon event 4: service started, Sysmon v13.33 | Monitoring service started |
| 04:37:18.858 | Sysmon process creation for `Sysmon64.exe` and `unsecapp.exe` | Routine-looking activity, not independently malicious |
| 04:43:46.320 | Sysmon event 1: `vmtoolsd.exe` spawned `cmd.exe` to execute `resume-vm-default.bat` as SYSTEM | Likely VMware resume behavior, requires contextual validation |
| 04:43:46.324 | `conhost.exe` child of that `cmd.exe` | Consistent with console activity |
| 04:43:46.351 | `ipconfig.exe /renew` child of the same `cmd.exe` | Consistent with network renewal during VM resume |
| 04:43:56.043 | `dllhost.exe` as `TEST\\Administrator`, logon ID `0x67589` | Administrator-associated process |
| **04:44:15.214** | **Security event 1102: Security log cleared**, account `TEST\\Administrator`, subject logon ID `0x67589`; record ID 12136 | **High-priority investigation point** |
| 04:45:04.818–.827 | Four Security 4769 service ticket requests: `DC1$@TEST.LOCAL` to `DC1$`, client `::1`, status `0x0`, encryption `0x12` | Local, successful Kerberos service ticket activity, not by itself malicious |
| 04:46:24.016 | `sc.exe start wuauserv` as SYSTEM, parent `svchost.exe -k netsvcs` | May be service administration; no causal link to 1102 shown |
| 04:47:45.170 | Another `dllhost.exe` as `TEST\\Administrator`, logon ID `0x67589` | Same logon session context |
| 04:47:48.266 | `mmc.exe` opening `eventvwr.msc`, launched by `Explorer.EXE`, as `TEST\\Administrator`, logon ID `0x67589` | Event Viewer opened **after** log clearing; cannot explain earlier 1102 on this evidence alone |

Additional Sysmon event 5 process termination detections occurred in between those timeline points; their full process attribution was not included in the evidence reviewed.

## Process Tree: VMware Tools

Sysmon process identifiers support this parent-child activity:

```text
vmtoolsd.exe
└── cmd.exe /c "...\\resume-vm-default.bat"  [PID 4524, SYSTEM, Logon ID 0x3e7]
    ├── conhost.exe                         [ParentPID 4524]
    └── ipconfig.exe /renew                 [ParentPID 4524]
```

The behavior is **plausibly benign** for a resumed VMware guest. The `SYSTEM` context is not, by itself, proof of maliciousness.

## Cross-Log Correlation: Administrator Session

These events were observed on `dc1.test.local` and reference the same `Logon ID: 0x67589`:

| Timestamp (-05:00) | Source | Event | Context |
|---|---|---|---|
| 04:43:56.043 | Sysmon | Event 1, `dllhost.exe` | `TEST\\Administrator` |
| 04:44:15.214 | Windows Security | Event 1102, Security log cleared | Subject: `TEST\\Administrator` |
| 04:47:45.170 | Sysmon | Event 1, `dllhost.exe` | `TEST\\Administrator` |
| 04:47:48.266 | Sysmon | Event 1, `mmc.exe eventvwr.msc` | `TEST\\Administrator` |

This is evidence of activity in the **same account/session context**, not evidence that `dllhost.exe` or `mmc.exe` performed the clearing. No definitive responsible process was identified. Since the recorded Event Viewer launch is more than three minutes later, it cannot simply be assigned as the cause of the preceding clear event.

## Kerberos Review

Four Security 4769 events (records 12161–12164) were reported at 04:45:04, from `::1` (IPv6 localhost), for machine account `DC1$` and service `DC1$`. All show success status `0x0` and ticket encryption type `0x12` (AES256).

These details are **consistent with local machine/service authentication**; they do not, by themselves, establish Kerberoasting, lateral movement or Zerologon exploitation.

## Verdict

**Confirmed from analyzed telemetry:** Security log cleared on `dc1.test.local` under `TEST\\Administrator` session `0x67589`.

**Correlated:** Sysmon processes in that same logon session; separate likely VMware guest-resume process chain.

**Not confirmed:** User identity, authorization, initiating process for clearing Security logs, malicious intent, account compromise, or CVE-2020-1472 (Zerologon) exploitation.

**Assessment:** High-priority alert for further investigation, not an established intrusion. The presence of “Zerologon” in sample filenames is not proof of an exploit.

## Recommended Next Steps

1. Identify the owner and intended use of `TEST\\Administrator` during the recorded timeframe, including any authorized lab actions or administration.
2. Review raw Security 1102 and nearby 4624/4672/4688/4634 events (when available) for session source, privileges, processes and attribution.
3. Review raw Sysmon Event 1 process tree and any relevant Event 3 network telemetry beyond the current Hayabusa detection subset.
4. Collect Netlogon, domain controller operational logs and relevant network telemetry before making Zerologon-specific claims.
5. Preserve evidence and document sample provenance, timestamps and hash values if preparing a formal case handoff.

## Reproduction (Analyst Lab)

```bash
cd ~/SOC-Labs/hayabusa-tool
./hayabusa-4.3.1-lin-x64-gnu dfir-timeline \
  -d ../case-006 \
  -o case-006-timeline.csv \
  -w
```

The analyst inspected the CSV using Python's `csv.DictReader`, counted detections by `EventID` and `RuleTitle`, extracted key detections, searched for the administrator logon ID, and sorted the timestamps to establish a timeline.

## Ethical Scope

Investigation of publicly distributed training logs only. No live environment was targeted; no incident impact or exploitation is asserted.
