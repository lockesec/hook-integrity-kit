# Events: findings for a SIEM

`verify --format jsonl` and `audit --format jsonl` print one JSON object per line: one per
finding, and always one `RUN` event last. `session-start --events FILE` appends the same events
to a local file each session, for a shipper you already run (Filebeat, Vector, rsyslog, the
Splunk forwarder) to collect. The kit sends nothing over the network.

The `RUN` event is the point. A run that found nothing is a positive "checked, clean" record,
and a run that could not look is `evaluable: false` with the cause. A dashboard can therefore
alert on drift AND on hosts that stopped reporting, instead of reading silence as clean.

## Fields

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `hook-integrity-kit.finding/1`; a breaking change bumps the number |
| `event_time` | string | UTC, ISO 8601, seconds |
| `host` | string | the machine's host name |
| `project` | string or null | the project root the check ran on (null when it could not be found) |
| `source` | string | `verify`, `session-start` or `audit` |
| `kind` | string | see below |
| `severity` | string | `high`, `medium` or `info` |
| `evaluable` | bool | false when this event records something the kit could not check |
| `detail` | string | the path, item or reason, as the text report prints it |
| `attack` | list | Enterprise ATT&CK technique ids (v20), possibly empty |
| `status`, `counts` | `RUN` only | `clean`, `drift`, `no-baseline` or `error` (verify); `listed`, `flagged` or `error` (audit); findings per kind |
| `path`, `registration`, `flags`, `notes` | `AUTO_RUN` only | where it is declared, what kind of registration, why it is flagged or noted |

## Kinds and ATT&CK

| Kind | Severity | ATT&CK | What happened |
|---|---|---|---|
| `MODIFIED` | high | T1546, T1554 | a blessed hook script or module changed |
| `ADDED` | high | T1546 | a file is registered or imported that the baseline does not have |
| `SETTINGS` | high | T1546 | the `hooks` block, execution env or a hook-control key changed |
| `ESCALATED` | high | T1685 | a permission was widened (`bypassPermissions`, a broad allow rule) or hooks disabled |
| `BYTECODE` | high | T1554 | a cached `.pyc` no longer matches its source |
| `KIT_CHANGED` | high | T1685 | the kit's own code changed since the bless |
| `REMOVED` | medium | | a blessed file is missing |
| `GLOBAL` | medium | T1546 | the user-level `~/.claude` hook surface changed (warn-only) |
| `UNREGISTERED` | info | | a new hook file on disk that nothing registers |
| `NOT_CHECKED` | info | | a surface the kit names but does not read; `evaluable: false` |
| `AUTO_RUN` | high, medium or info | T1546 | `audit`: something that runs on its own; high when flagged, medium with a review note |
| `NOT_EVALUABLE` | medium | | `audit`: a config that could not be read; `evaluable: false` |
| `RUN` | by status | | the run itself, always last |

T1546 Event Triggered Execution and T1554 Compromise Host Software Binary are the techniques
MITRE lists for the Mini Shai-Hulud worm (S9043), which plants exactly these hooks. T1685
Disable or Modify Tools is v20's id for disabling a defensive tool; it replaced T1562.001,
which is revoked in v20. Every id here was read in MITRE's v20 STIX data, and a test pins the
set.

## Samples

```json
{"attack": ["T1546"], "detail": ".claude/setup.mjs", "evaluable": true, "event_time": "2026-10-17T01:02:28+00:00", "host": "dev-01", "kind": "ADDED", "project": "/srv/app", "schema": "hook-integrity-kit.finding/1", "severity": "high", "source": "verify"}
{"attack": [], "detail": ".claude/setup.mjs is reached from SessionStart and is not shell or Python: hashed, but what it runs is not followed", "evaluable": false, "event_time": "2026-10-17T01:02:28+00:00", "host": "dev-01", "kind": "NOT_CHECKED", "project": "/srv/app", "schema": "hook-integrity-kit.finding/1", "severity": "info", "source": "verify"}
{"attack": [], "counts": {"ADDED": 1, "NOT_CHECKED": 1, "SETTINGS": 1}, "evaluable": true, "event_time": "2026-10-17T01:02:28+00:00", "global_status": "off", "host": "dev-01", "kind": "RUN", "project": "/srv/app", "schema": "hook-integrity-kit.finding/1", "severity": "high", "source": "verify", "status": "drift"}
```

Each host's latest `RUN`, where it could not look:

```console
jq -s 'map(select(.kind == "RUN")) | group_by(.host) | map(max_by(.event_time))
       | map(select(.evaluable | not)) | .[] | {host, project, status, detail}' events.jsonl
```

## Sigma

Two rules in [sigma/](sigma/), written to the Sigma specification and not yet validated with
sigma-cli:

- `hook_integrity_kit_drift.yml`: high-severity, evaluable events from this kit (a custom log
  source; map `product: hook-integrity-kit` to wherever your shipper lands the JSONL).
- `agent_hook_surface_written_by_package_install.yml`: on Linux endpoints with Sysmon for
  Linux, a write to `.claude/settings.json`, `.claude/settings.local.json`, `.mcp.json` or
  `.vscode/tasks.json` by `node`, `bun` or a shell whose parent runs from `node_modules` or a
  package manager: the way Mini Shai-Hulud wrote its hooks. It catches the write as it
  happens, where `verify` catches the result at the next session. The same idea as Securonix's
  published Mini Shai-Hulud analytic, extended to the MCP config.
