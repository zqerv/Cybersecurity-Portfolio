# SOC Investigation 005 — PowerShell 2.0 Downgrade Detection

> **Authorized lab analysis:** This report documents the analyst's examination of a publicly available training EVTX sample with Hayabusa. It is **not** an incident involving the analyst's own employer or a claim of real-world compromise.
>
> **Verdict:** PowerShell 2.0 engine execution confirmed in the sample; malicious intent or host compromise **not confirmed**.

## Investigation Summary

An analyst examined the sample `YamatoSecurity/ImpairDefenses/T1562.010_DowngradeAttack_PowerShell.evtx` from the [Yamato Security Hayabusa sample EVTX repository](https://github.com/Yamato-Security/hayabusa-sample-evtx).

Hayabusa 4.3.1 generated four detection rows, two of which mapped to the **same underlying Windows event** at 2021-01-28 05:40:54.884 -05:00. One rule identified a PowerShell engine start, and the second reported a medium-severity PowerShell 2.0 downgrade detection.

## Tools and Method

- Kali Linux lab environment
- Hayabusa 4.3.1, `dfir-timeline` command
- Hayabusa CSV and super-verbose JSON output
- Python `csv.DictReader` and `json.JSONDecoder` for reviewing detection exports

The analyst inspected **Hayabusa's parsed output**. The complete original EVTX XML was not independently parsed or validated in this exercise because an attempted Python EVTX reader encountered a missing dependency (`Evtx._vendor`).

## Evidence Table

| Field | Observed value |
|---|---|
| Computer | `DESKTOP-ST69BPO` |
| Channel | `PwShClassic` |
| Windows Event ID | `400` |
| Event Record ID | `729` |
| Timestamp | `2021-01-28 05:40:54.884 -05:00` |
| HostName | `ConsoleHost` |
| HostVersion | `2.0` |
| EngineVersion | `2.0` |
| HostApplication | `n/a` |
| CommandLine | Empty |
| ScriptName | Empty |
| RunspaceId | `c6e94dca-0daf-418c-860a-f751a9f2cbe1` |
| Detection title | `PwSh 2.0 Downgrade Attack` |
| Hayabusa rule level | `med` |
| Rule status | `test` |
| Rule file | `PwShClassic_400_Med_PwShStarted_V2DowngradeAttack.yml` |

## Timeline (Source Time Zone: -05:00)

| Time | Finding | Interpretation |
|---|---|---|
| 04:58:44.538 | Event 400, PowerShell engine 5.1, `HostApplication: powershell calc` | Earlier engine start |
| 05:22:26.382 | Event 400, PowerShell engine 5.1, `HostApplication: C:\Windows\System32\sdiagnhost.exe -Embedding` | Another engine start |
| 05:40:54.884 | Event 400, Record 729, engine 2.0 | Older PowerShell engine started |
| 05:40:54.884 | Hayabusa downgrade rule, Record 729 | Second rule match for the same event |

**Deduplication:** The four rows in the Hayabusa detection output do not represent four distinct Windows event records. Record 729 triggered both the generic engine-start rule and the downgrade-detection rule.

## Analysis

- `EngineVersion=2.0` and `HostVersion=2.0` support that a PowerShell 2.0 engine started.
- A legacy engine can reduce security logging visibility compared with modern PowerShell versions; this merits triage.
- The detection rule's `med` severity and `test` status are **rule metadata**, not definitive confirmation of malicious activity.
- `HostApplication: n/a`, empty `CommandLine`, empty `CommandName`, and empty `ScriptName` do **not** establish which process initiated the engine, which command was invoked, or who initiated it.
- Although other PowerShell 5.1 starts precede this event, these records alone do not prove that the same session or user deliberately switched engines.

## Decision

**Suspicious PowerShell 2.0 execution; investigate further.**

**Confirmed:** a PowerShell 2.0 engine-start event was recorded and matched a Hayabusa downgrade detection rule.

**Not confirmed:** unauthorized access, an attacker identity, deliberate defense evasion, malware, data theft or host compromise.

## Recommended Follow-up

1. Obtain surrounding original EVTX records and independently inspect the raw event XML.
2. Correlate Security 4688 and/or Sysmon Event 1 (if available) for process creation, parent process, command line, timestamps and user context.
3. Review PowerShell operational logs (including script block logging if available), EDR process telemetry and administrative change tickets.
4. Identify whether PowerShell 2.0 is required by a legitimate legacy application. If not, consider disabling the optional legacy engine in accordance with organizational change controls.
5. Escalate if additional evidence establishes deliberate downgrading or other unauthorized activity.

## Reproduction

From the Hayabusa installation directory:

```bash
./hayabusa-4.3.1-lin-x64-gnu dfir-timeline \
  -f "../hayabusa-sample-evtx/YamatoSecurity/ImpairDefenses/T1562.010_DowngradeAttack_PowerShell.evtx" \
  -t json -p super-verbose \
  -o powershell-detailed.json -w
```

Hayabusa JSON output in this exercise contained multiple top-level JSON objects, so a single `json.load()` produced `JSONDecodeError: Extra data`. The analyst used `json.JSONDecoder().raw_decode()` iteratively to parse and filter `RecordID == 729`.

## Evidence Integrity and Limitations

This is a public **training sample**. The analysis relies on the specific output pasted from the analyst's Kali environment. No cryptographic hash of the original sample file or screenshot evidence was collected for this report, and no source host was accessed. Further process attribution requires telemetry not currently available in the submitted evidence.

## Ethical Scope

The investigation used downloadable practice logs only. No unauthorized access or scanning was conducted.
