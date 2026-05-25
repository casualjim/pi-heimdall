## Context

Current `@ifi/pi-background-tasks` has the right user experience for long-running commands: explicit `bg_task` spawning, `bg_status`, `/bg`, task ids, PID compatibility, log files, dashboard/watch UI, and follow-up wakeups. It also intentionally no longer overrides ordinary `bash` calls.

The blocker is security, not UX. `@ifi/pi-background-tasks` launches commands with raw local shell `spawn()`, so those commands bypass Heimdall's `bash` sandbox path. Users who require sandboxed command execution cannot safely use that package as-is.

The solution is to fork the useful task-management behavior into Heimdall as a separate optional extension resource in the same package. It should be a safe implementation of the same tasks, not a new namespaced alternative.

## Goals / Non-Goals

**Goals:**

- Provide a drop-in safe replacement for `@ifi/pi-background-tasks` using the same public surfaces: `bg_task`, `bg_status`, `/bg`, `Ctrl+Shift+B`, task ids, PID compatibility, logs, dashboard/watch, and follow-up notifications.
- Ship it as a separate extension resource in `@casualjim/pi-heimdall` so users can enable or disable it independently from the core Heimdall guard extension.
- Launch background commands only through Heimdall's sandbox launch path.
- Fail closed when sandboxing is disabled, unavailable, or misconfigured.
- Keep ordinary `bash` foreground semantics unchanged.
- Preserve current `@ifi/pi-background-tasks` explicit-spawn behavior rather than resurrecting old timeout-to-background behavior.

**Non-Goals:**

- Supporting unsandboxed background execution from Heimdall.
- Avoiding tool-name conflicts with `@ifi/pi-background-tasks`; the same names are intentional because this is the safe replacement.
- Adding `heimdall_bg_task`/`heimdall_bg_status` aliases.
- Requiring an additional `backgroundTasks.enabled` config flag after the optional extension resource is enabled.
- Persisting task state across Pi restarts.
- Turning Heimdall into a general process manager outside Pi background task needs.
- Changing native sandbox policy semantics.

## Decisions

### Make background tasks a separate optional extension resource

The core Heimdall extension should continue to own guards and sandboxed `bash`. Sandboxed background tasks should live in a separate extension file, for example:

```text
extensions/heimdall.ts
extensions/heimdall-bg-tasks.ts
```

Users enable or disable the feature through Pi package resource selection/filtering. Loading the background-task extension resource is sufficient to register the background-task surfaces; there is no second Heimdall config gate. Normal core Heimdall use should not require accepting a background-task tool surface.

The background-task extension may share config loading and sandbox launch code with the core extension, but it should not depend on mutable in-memory state owned by another extension instance. Shared code should be extracted into importable helpers where needed.

### Keep the same public names

The extension should register the same public names as `@ifi/pi-background-tasks` when enabled:

```text
bg_task
bg_status
/bg
Ctrl+Shift+B
```

This is intentionally conflicting with `@ifi/pi-background-tasks`. Users should disable the upstream background-task extension/package when enabling Heimdall's safe implementation.

This avoids teaching the model two competing task APIs and preserves existing prompts/workflows that already know `bg_task` and `bg_status`.

### Pin the compatibility baseline and deviations

The behavioral baseline is the `@ifi/pi-background-tasks` package version present in the current `oh-pi` source used for this change: `0.5.1`.

The safe replacement should preserve these public contract points:

- `bg_task` actions: `spawn`, `list`, `log`, `stop`, `clear`
- `bg_task` parameters: `command`, `id`, `pid`, `title`, `cwd`, `reactToOutput`, and `notifyPattern` with the same action relevance as upstream
- `bg_status` actions: `list`, `log`, `stop`
- `bg_status` PID-based lookup for `log` and `stop`
- task ids like `bg-1`, PID lookup, status vocabulary (`running`, `completed`, `failed`, `stopped`), exit-code reporting, task summaries, and unknown task errors
- `/bg` command flows: dashboard/list, `run`, `watch`, `watch --follow`, `stop`, and `clear`
- `Ctrl+Shift+B` dashboard shortcut
- output buffering and bounded tail behavior compatible with upstream defaults (`5000` character log tails, `3000` character alert tails, `120000` character in-memory output buffer, and `1500ms` output-settle delay)
- explicit background task expiry compatible with upstream default behavior (`10 minutes` by default for explicitly spawned tasks)
- `reactToOutput` defaulting to `true`, with optional substring or `/regex/flags` gating through `notifyPattern`

Intentional deviations from upstream are:

- every process launch uses Heimdall's sandbox runtime instead of raw local shell `spawn()`
- spawn fails closed when sandboxing is disabled, unavailable, or misconfigured
- background commands run Heimdall command preflight protections before launch
- model-visible background output is redacted consistently with Heimdall foreground `bash` output
- logs use Heimdall's private secure log storage policy instead of upstream's public temp-file convention

### Fork behavior, replace launch mechanism

Use `@ifi/pi-background-tasks` as the behavioral template for task lifecycle and UI:

- explicit `bg_task action=spawn` starts a task
- task ids such as `bg-1`
- PID-compatible lookup for `bg_status`
- log files for full command output
- bounded tails/previews in tool responses and follow-up messages
- `/bg` list/watch/stop/clear flows
- dashboard overlay and `Ctrl+Shift+B` shortcut
- follow-up messages on output and exit
- cleanup on session shutdown

Replace the raw shell launcher with a Heimdall sandbox launcher:

```text
bg_task spawn
  -> build native sandbox policy for command/cwd
  -> spawn heimdall-sandbox exec --policy -
  -> write policy JSON to stdin
  -> stream stdout/stderr into task buffers and logs
```

The existing `createSandboxedBashOps` helper waits for command completion and is shaped for foreground execution. Background tasks need a lower-level launch helper that returns the child process and owns process-group cleanup. Foreground `bash` can then use that helper and wait for close; background tasks can attach lifecycle listeners and return immediately.

### Fail closed: no sandbox, no background process

The background-task extension must never run a command through raw local `spawn()` as a fallback.

Failure cases should return an error and start no process:

- `sandbox.enabled` is false
- `--no-sandbox` disabled sandboxing for the session
- `heimdall-sandbox` binary is missing or cannot launch
- policy generation or config validation fails
- the requested cwd does not exist
- a Heimdall command preflight check blocks the command

This is stricter than foreground `bash` fallback behavior because the entire reason for this extension is safe background execution.

### Preserve Heimdall command protections for background commands

Existing command protections mostly listen for `bash` tool calls. A `bg_task` command string would otherwise bypass those preflight checks because it is a different tool.

The background-task extension should apply equivalent command preflight before launch, including relevant Heimdall checks such as command policies, secret-key reference blocking, risky kubectl command blocking, and sops decrypt blocking. Implementation can do this by extracting reusable command-check helpers from the existing guards rather than trying to synthesize a fake `bash` tool call.

Tool-visible output from background tasks (`bg_task`, `bg_status`, `/bg` notifications, and follow-up messages) should use the same redaction behavior where Heimdall has loaded secret values. The raw log file remains command output produced inside the sandbox; bounded responses and model-visible messages should avoid reintroducing output that the foreground `bash` path would redact.

### Store logs in Heimdall-private storage

Background logs are command output from a sandboxed process. They may still contain anything the sandboxed command was allowed to print, so storage must not follow upstream's public temp-file convention.

The extension should store logs under a Heimdall/Pi private runtime directory, for example beneath `getAgentDir()/heimdall/background-tasks/`, with directory permissions equivalent to `0700` and log file permissions equivalent to `0600`. Filenames should include task identity for usability but also include a non-guessable component; callers must not be able to choose log file paths.

The extension should delete log files for finished tasks when `bg_task action=clear` removes those tasks. On session shutdown, it should terminate running tasks, clear the in-memory task map, and make a best-effort attempt to remove tracked log files. Tool responses and follow-up messages should still include the log path while the task is tracked.

### Keep process ownership explicit

Every background task should track enough process metadata to clean up safely:

- task id
- PID
- process group where available
- command
- cwd
- log path
- status
- exit code
- timestamps
- output buffer metadata

Stop and shutdown cleanup should prefer process-group termination for sandboxed launches and fall back to single-PID termination only when necessary.

## Risks / Trade-offs

- Same public tool names create conflicts if users enable both implementations → This is intentional; docs must make the replacement relationship explicit.
- Keeping the extension separate but in the same package requires clear Pi package filtering/configuration docs.
- Refactoring sandbox launch helpers may affect foreground `bash` behavior → Preserve existing tests and add regression coverage.
- Background command preflight must not drift from foreground `bash` guard behavior → Extract shared helpers rather than duplicating regex/policy logic where possible.
- Follow-up messages can be noisy → Match the `@ifi/pi-background-tasks` behavior first; users enabling this extension are choosing that workflow.
- Secure log retention intentionally differs from upstream temp-file behavior → Document the deviation and test cleanup behavior.

## Migration Plan

1. Keep the core Heimdall extension unchanged for users who do not enable background tasks.
2. Add the optional background-task extension resource in the same package.
3. Fork the needed `@ifi/pi-background-tasks` task manager behavior into Heimdall.
4. Refactor Heimdall sandbox launch code so both foreground `bash` and background tasks can use the same native `heimdall-sandbox exec --policy -` launch primitive.
5. Add preflight checks so background commands do not bypass Heimdall command protections.
6. Store logs in Heimdall-private storage and clean them up when tasks are cleared or sessions shut down.
7. Document that Heimdall's background-task extension replaces `@ifi/pi-background-tasks` and uses the same names, so the upstream package/extension must be disabled.
