## Why

`@ifi/pi-background-tasks` provides the right long-running command workflow, but it launches tasks with raw local `spawn()` outside Heimdall's sandbox boundary. For users who require Heimdall sandboxing, that makes the existing background-task package unusable even though its task UI, logs, `bg_task`, `bg_status`, `/bg`, and follow-up behavior are valuable.

Heimdall should provide a safe drop-in implementation of the same background-task surface from within the `@casualjim/pi-heimdall` package, while letting users enable or disable it independently from the core Heimdall guard extension.

## What Changes

- Add a separate optional Heimdall extension for sandboxed background tasks in the same package as the core Heimdall extension.
- Use `@ifi/pi-background-tasks` as the behavioral starting point: `bg_task`, `bg_status`, `/bg`, `Ctrl+Shift+B`, task ids, PID compatibility, log files, dashboard/watch flow, and reactive completion/output follow-ups.
- Register the same public tool and command names, not Heimdall-prefixed aliases. Users who enable Heimdall's background-task extension should disable `@ifi/pi-background-tasks` because the conflict is intentional: Heimdall is the safe replacement.
- Launch every background command only through Heimdall's sandbox runtime using the effective sandbox policy for the command cwd.
- Fail closed when sandboxing is disabled, unavailable, or misconfigured. The background-task extension must never fall back to raw local `spawn()` execution.
- Apply the same relevant Heimdall command preflight protections and model-visible output redaction behavior that protect foreground sandboxed `bash` commands.
- Leave ordinary `bash` behavior alone. This change does not add timeout-to-background behavior to Heimdall's existing `bash` override.
- Document how to enable the optional extension and how to disable the unsafe upstream background-task package when sandboxed background tasks are required.

## Capabilities

### New Capabilities

- `sandboxed-background-tasks`: optional drop-in background shell task management compatible with `@ifi/pi-background-tasks`, but sandboxed by Heimdall and fail-closed when sandboxing is unavailable.

### Modified Capabilities

None.

## Impact

- Affected code: new optional extension resource, shared sandbox launch support, guard/preflight helpers, tests, and docs.
- Affected tools/commands when enabled: `bg_task`, `bg_status`, `/bg`, and `Ctrl+Shift+B`.
- Affected docs: README installation/configuration notes for enabling Heimdall's safe background tasks and disabling `@ifi/pi-background-tasks`.
- Dependencies: no new runtime dependency expected; fork only the needed behavior from `@ifi/pi-background-tasks` and reuse Node.js process/filesystem APIs plus Heimdall's native sandbox runtime.
