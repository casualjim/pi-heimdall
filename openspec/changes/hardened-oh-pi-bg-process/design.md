## Context

Heimdall's `sandbox-guard` already owns the `bash` tool so it can route commands through bubblewrap when sandboxing is active. `oh-pi`'s `bg-process.ts` also owns `bash`, adding a useful workflow: commands that run longer than 10 seconds are kept alive in the background, return PID/log information, and notify the agent on completion.

The conflict is not about the idea of backgrounding; it is about two extensions registering the same tool name. The simpler solution is to absorb the one conflicting plugin behavior into Heimdall's existing `bash` owner, changing only the launch path from raw `spawn("bash", ["-c", command])` to Heimdall's foreground/sandbox execution choice.

## Goals / Non-Goals

**Goals:**

- Match `oh-pi` `bg-process.ts` behavior closely enough that users can disable that plugin and keep the same workflow.
- Keep Heimdall as the single owner of the `bash` tool.
- Run backgrounded commands through Heimdall's sandbox when sandboxing is active.
- Preserve the same PID/log/status/completion-message style that `oh-pi` users expect.
- Keep the implementation small: an in-memory PID map, timeout-to-background path, `bg_status`, and shutdown cleanup.

**Non-Goals:**

- Designing a new generic process manager.
- Adding persistent process state across pi restarts.
- Adding generated stable IDs when OS PIDs are enough for parity.
- Adding extra log filtering or withholding output beyond `oh-pi`-style preview/tail behavior.
- Reworking unrelated guards or changing foreground command semantics beyond the background timeout behavior.

## Decisions

### Port the plugin behavior, do not redesign it

The implementation should use the `oh-pi` extension as the behavioral template:

- default background threshold: 10 seconds
- explicit `timeout` parameter overrides the default threshold
- command still running after threshold returns PID, log path, stop hint, output preview, and completion notice text
- command finishing before threshold returns normal combined stdout/stderr and exit info
- `bg_status` supports `list`, `log`, and `stop`
- unfinished background processes are terminated on session shutdown

This keeps migration predictable and avoids turning a compatibility fix into a larger architecture project.

### Reuse the existing Heimdall launch path

`oh-pi` launches commands with raw local shell execution. Heimdall should launch foreground and background commands through the same internal launch path: sandboxed when the sandbox is active, local shell fallback otherwise.

This change should not redesign sandbox policy, configuration, or platform isolation. It should only ensure a command that crosses the backgrounding threshold keeps running through the same launch decision that a foreground `bash` command would have used.

### Treat background logs like delayed bash output

Background logs are command output. The sandbox and existing command guards control what the command can access; the background feature should not invent a separate information policy. It should keep `oh-pi`-style behavior: full output is written to the log file, tool responses show bounded previews/tails, and completion messages include the same style of output tail.

The key safety property is that the command itself ran through Heimdall's allowed execution path. If the foreground `bash` command could print something, the backgrounded command may print the same thing later.

### Keep the management surface compatible

Register `bg_status` with the same actions and parameter shape as `oh-pi` where possible:

```text
action: list | log | stop
pid?: number
```

This makes existing model behavior and documentation transfer directly.

## Risks / Trade-offs

- Always-on 10 second backgrounding changes current Heimdall-only behavior → This is intentional for replacing `oh-pi`'s plugin; document it clearly.
- A backgrounded sandbox process may need sandbox resources after the original tool call returns → The launch path must own any per-process cleanup until the process exits or is stopped.
- `process.kill(pid)` may not stop child process groups in every case → Prefer process-group termination when Heimdall launches detached processes, with single-PID kill as fallback.
- Completion messages can be noisy → Preserve `oh-pi` parity first; users already opting into this workflow expect completion output.
- Logs can contain anything the command was allowed to print → This matches foreground `bash`; sandbox/path/env policy remains the boundary.

## Migration Plan

1. Keep README troubleshooting guidance telling users to disable `oh-pi`'s `bg-process.ts` when using Heimdall.
2. Implement `oh-pi`-compatible backgrounding inside Heimdall's existing `bash` override.
3. Add/adjust tests for the compatibility behavior and sandbox launch path.
4. Document that Heimdall now replaces the disabled `oh-pi` plugin.

## Open Questions

- Should the log filename keep the `oh-pi-bg-*.log` prefix for familiarity, or use a `heimdall-bg-*.log` prefix to show ownership?
- Should stop use process-group kill by default while still showing the familiar `kill <pid>` hint in tool output?
