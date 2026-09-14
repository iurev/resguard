# resguard

Linux resource limits for agent shell commands (Codex, pi), with permanent local
audit logs.
Codex itself remains uncapped, and its dangerous-mode permissions are unchanged.
This is a local command hook and CLI, not an MCP server or an always-on watcher.

## How it works

A `PreToolUse` command hook rewrites shell calls to a runner. Before executing
the original command, the runner creates a systemd user service and verifies
the actual cgroup limits. A shared `resguard.slice` constrains the aggregate
resource usage of intercepted jobs for the account. Per-command memory, CPU and
task limits are separate from the aggregate pool limits, so several legitimate
services do not all compete inside one command's budget.

Final accounting runs in a separate, transient `resguardlog.slice`, not in
the workload's shutdown hook. Slow or failed accounting cannot turn a successful
command into a workload timeout. The logger has a 30-second deadline, 64 MiB
memory/25% CPU/8-task limits per job, and a shared 256 MiB/100% CPU/64-task
ceiling, with no swap. These small accounting budgets are separate from workload
limits; Codex itself is unchanged. The workload still has a three-second stop
grace. No always-on logging daemon is installed.

- Memory maximum/high watermark, zero swap, CPU quota and process/thread limit.
- Command deadline and cleanup of background/detached descendants in the job.
- Optional disk bandwidth limits, when the I/O controller is delegated.
- Preserved working directory, environment, umask, streams and shell exit status.
- Terminal input and resize forwarding.
- Local command/resource records and a recent-job report.

## Requirements

Linux with cgroup v2, an active systemd user manager, and delegated `cpu`,
`memory` and `pids` controllers. Disk throttling additionally requires `io`
delegation. The service manager must support the D-Bus properties used by the
runner, including `ExtraFileDescriptors`; unsupported versions are not assumed
compatible.

The system Python at `/usr/bin/python3` needs `dbus-python` and PyGObject/GLib.
The runner uses Linux `memfd` and `pidfd` interfaces. The full integration suite
also needs Bash and Zsh. Codex must support command hooks, input rewriting,
hook trust review, and the `hooks/list` app-server method used by diagnostics.

## Install separately from the checkout

The checkout is source only. Runtime, policy and private state belong in the
executing Linux account's home, which is independent of the command's working
directory. A custom `CODEX_HOME` needs separate hook-path verification.

For a fresh installation, run from this checkout as the account that runs Codex:

```sh
RESGUARD_ACCOUNT_HOME="$(/usr/bin/python3 -c 'import os,pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')"
install -d -m 700 "$RESGUARD_ACCOUNT_HOME/.local/lib/resguard/bin" \
  "$RESGUARD_ACCOUNT_HOME/.local/bin" "$RESGUARD_ACCOUNT_HOME/.config/resguard"
install -m 644 ./*.py "$RESGUARD_ACCOUNT_HOME/.local/lib/resguard/"
install -m 755 bin/systemd-run "$RESGUARD_ACCOUNT_HOME/.local/lib/resguard/bin/systemd-run"
install -m 755 bin/resguard "$RESGUARD_ACCOUNT_HOME/.local/bin/resguard"
```

Keep `.local/bin` on the account's `PATH`. For upgrades, back up the installed
runtime first and keep the existing policy, hook configuration and audit history.
Do not blindly overwrite an existing installation. Prefer upgrading between
jobs. This accounting fix preserves the legacy `finalize` entry point and request
format, so an atomic single-file replacement of `guard.py` is also compatible
with in-flight jobs. Existing units keep their old shutdown configuration until
they finish; newly launched commands use separate accounting immediately. Do
not stop running workloads merely to upgrade. Preserve a rollback copy and
replace a fully written same-directory staging file atomically, not in place.

Create `.config/resguard/policy.json` in that account home from
[`policy.example.json`](policy.example.json). The example limits are starting
values, not a recommendation for every machine. Replace `/dev/REPLACE_ME` with
the appropriate existing local block device and choose budgets for the host.
Even with `require_io=false`, the current runner requires an existing device.
With `require_io=false`, missing I/O delegation permits execution without disk
throttling; use `true` if lack of disk throttling must block commands.

`memory_max`, `memory_high`, `tasks_max`, `cpu_percent`, and the two I/O
bandwidth fields apply to each command tree. Their `aggregate_` counterparts
apply to the shared workload slice. Aggregate values must be at least as large
as their per-command values.
Policies without aggregate keys remain compatible and use the per-command
values for the shared slice; add explicit aggregate values to avoid that old,
more restrictive behavior. Environment overrides only tighten per-command
limits and never rewrite the shared pool.

Merge this entry into the user-level Codex `hooks.json`, preserving unrelated
hooks. Replace `ABSOLUTE_ACCOUNT_HOME` with the account's actual home directory:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^Bash$",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/bin/python3 ABSOLUTE_ACCOUNT_HOME/.local/lib/resguard/hook.py",
            "timeout": 10,
            "statusMessage": "resguard: applying command resource limits"
          }
        ]
      }
    ]
  }
}
```

Enable the `hooks` feature in Codex configuration where required by the installed
version. Start a new Codex session and use `/hooks` to review and trust the exact
definition. Do not copy a trust hash from another installation. Matching hooks
from different configuration layers all run; remove duplicate resource-hook
registrations after reviewing them. See the [official hook documentation](https://learn.chatgpt.com/docs/hooks).

The diagnostic command compares the exact hook command with
`'/usr/bin/python3 ' + shlex.quote(absolute_hook_path)`. If your account path
contains spaces, use that quoting when constructing the JSON command string.

```sh
resguard status
resguard report --last 20
resguard logs
```

Accounting is registered with the workload in one `StartTransientUnit` call,
using an auxiliary unit and both `OnSuccess`/`OnFailure`. It survives outer-runner
cancellation. The runner waits for its independently bounded outcome; accounting
failure produces a warning, not a replacement command exit code. Check the
named `resguardlog-<job>.service` in the user journal for accounting failures.
Unlogged launched-job metadata stays in private `pending/` for diagnosis; only
abandoned, never-launched hook requests are automatically swept. Storage failure
can still prevent persistence: this is not a lossless guarantee on broken/full
storage. Secondary `return` records are best-effort; `finish` is authoritative.

`status` checks configuration, controller delegation and hook discovery/trust
for the current directory; it is not an end-to-end enforcement test. Each worker
independently checks its kernel limits before running a command. `logs` prints
the private log location. OOM returns 137, timeout 124, and runner failure 125.

### pi extension

The optional [`resguard.ts`](resguard.ts) extension guards the pi coding
agent's model-driven `bash` tool through the same installed trampoline. On
every `bash` tool call it sends the PreToolUse payload to `hook.py`, replaces
the command with the returned rewrite, or blocks the call when the guard
denies it or is unavailable. It fails closed and keeps the transcript showing
the original command; only execution is wrapped. The account home is resolved
at load time, so install the runtime above under the same account that runs
pi. Guarded jobs use the shared audit log, correlated by pi session and
tool-call identifiers.

Install it as that account:

```sh
install -d -m 700 "$RESGUARD_ACCOUNT_HOME/.pi/agent/extensions"
install -m 644 resguard.ts "$RESGUARD_ACCOUNT_HOME/.pi/agent/extensions/resguard.ts"
```

pi auto-discovers extensions in that directory: new sessions load it at
startup, running sessions need `/reload`. Scope matches the Codex `^Bash$`
matcher: the model's `bash` tool only. User-typed shell escapes and other
tools are not intercepted. Verify with a trivial prompt that runs `echo`
through the `bash` tool, then `resguard report --last 1`.

## Verification

On an installed host, run tests sequentially:

```sh
resguard test
```

This runs retention/concurrency tests, finite resource/failure probes, and a
terminal-resize test. Integration probes use tighter per-job ceilings and write
records to the account's private state. The memory fixture allocates at most
192 MiB against a 128 MiB limit; it is not an unbounded stress test. Keep the
test runner resource-limited as well. Testing should not overlap other heavy jobs.

Final-accounting regressions use private temporary state and finite sleep
delays, without filling RAM or locking the installed audit log. They verify
slow/failed logging, real runtime and descendant-cleanup timeouts, outer-runner
death, independent kernel accounting limits, unit collection, and legacy
finalizer compatibility.

When other guarded jobs are busy, run `/usr/bin/python3 -B test_isolated.py`
from the checkout instead. It creates private source/state fixtures and an
independent 512 MiB test-job budget with a 128 MiB test harness. Installed
policy, hooks, and existing workloads are not changed.

For isolated audit tests from this checkout:

```sh
/usr/bin/python3 -B test_audit.py
```

`live_codex_test.py` explicitly starts real dangerous-mode Codex sessions with
tighter child-command budgets. It uses the account's Codex configuration,
including configured integrations, may use network/model quota, and saves private
test transcripts. It is not part of `resguard test`. After reviewing the script
and the installed hook, run it manually, optionally with `--interactive` and
`--cwd`. `verify_live.py SESSION_ID [--interactive]` checks actual rollout and
kernel evidence; run it immediately, before log rotation or PID reuse.

`CODEX_GUARD_*` environment overrides can only lower policy limits and must be
set before launching the runner or Codex. Assignments inside the original
command happen too late to change its limits.

## Privacy and retention

State stays outside the checkout under `.local/state/resguard` in the account
home. Logs retain full command text, paths, session/tool/job identifiers,
timestamps, resource measurements and exit/error information. They do not retain
normal terminal output or environment-variable values. Secrets embedded directly
in command text are logged without automatic redaction.

Audit history is retained indefinitely. Active logs rotate at roughly 10 MiB
into numbered archives without automatic deletion. Reports stream across the
archives with bounded memory. Disk usage grows over time; this is local
retention, not a backup or a guarantee against disk-full/write failures.
Files are private to the account and root, not isolated from an agent running
under the same account. There is no resguard analytics/upload feature.

Do not commit real policies, user hook/config files, logs, transcripts, backups,
bytecode or local knowledge-graph data. The ignore rules are a convenience, not
a secret scanner; inspect staged files and commit metadata before publishing.

## Coverage limits

This is a guard against accidental overload, not a malicious-agent sandbox.
The same account can modify the code/configuration or bypass it. Absolute
launchers, direct D-Bus calls, existing daemons and MCP work can run outside
the guarded process tree. Shell startup and some native hook failure/skip paths
are not covered. The PATH-local `systemd-run` shim handles supported scope
wrappers, not every launcher. Output volume is not capped. I/O enforcement must
be verified on the target host; it is not implied by the presence of policy keys.
