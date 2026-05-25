## 1. Package and Optional Extension Surface

- [x] 1.1 Add a separate Heimdall background-task extension resource in the same package, e.g. `extensions/heimdall-bg-tasks.ts`.
- [x] 1.2 Ensure users can enable or disable the background-task extension independently from the core `extensions/heimdall.ts` extension through Pi package resource selection/filtering.
- [x] 1.3 Ensure normal core Heimdall usage does not register `bg_task`, `bg_status`, `/bg`, or the background task shortcut unless the background-task extension resource is enabled.
- [x] 1.4 Ensure enabling the background-task extension resource is sufficient to register the background-task surfaces and does not require an additional `backgroundTasks.enabled` config flag.
- [x] 1.5 Document that Heimdall's background-task extension intentionally uses the same names as `@ifi/pi-background-tasks` and users must disable the upstream implementation to avoid tool/command conflicts.

## 2. Fork `@ifi/pi-background-tasks` Behavior

- [x] 2.1 Port the needed task model, task id/PID lookup, output buffering, log file handling, tail/truncation helpers, status formatting, and task lifecycle behavior from `@ifi/pi-background-tasks` version `0.5.1`.
- [x] 2.2 Register the same public `bg_task` tool actions: `spawn`, `list`, `log`, `stop`, and `clear` with compatible parameters and error behavior.
- [x] 2.3 Register the same public `bg_status` compatibility actions: `list`, `log`, and `stop` with PID-oriented behavior and compatible missing/unknown PID errors.
- [x] 2.4 Register `/bg` management flows for dashboard/list, `run`, `watch`, `watch --follow`, `stop`, and `clear`.
- [x] 2.5 Register the same background task shortcut (`Ctrl+Shift+B`).
- [x] 2.6 Preserve reactive follow-up messages for output and task exit, including bounded output tails, `reactToOutput` default behavior, `notifyPattern` matching, and task metadata.
- [x] 2.7 Document intentional compatibility deviations: sandbox-only launch, fail-closed behavior, guard preflight, output redaction, and private secure log storage.

## 3. Sandboxed Launch Integration

- [x] 3.1 Refactor the existing sandboxed bash implementation to expose a lower-level native sandbox launch helper that returns the child process and policy metadata instead of only waiting for completion.
- [x] 3.2 Keep foreground `bash` behavior unchanged by rebuilding `createSandboxedBashOps` on top of the lower-level launch helper.
- [x] 3.3 Use the lower-level launch helper for every background task spawn.
- [x] 3.4 Generate a per-task native policy containing configured sandbox policy fields plus runtime cwd, `bash -c <command>` argv, and `stdio: "piped"`.
- [x] 3.5 Fail background task spawn without starting a process when sandboxing is disabled, `--no-sandbox` is active, the sandbox binary is unavailable, policy generation/config validation fails, or the cwd is missing.
- [x] 3.6 Ensure stop and shutdown cleanup terminate the sandboxed process group where possible, with single-PID fallback only when process-group termination is unavailable.
- [x] 3.7 Add foreground `bash` regression coverage proving the background-task extension does not add timeout-to-background behavior or alter existing foreground timeout, guard, or sandbox semantics.

## 4. Heimdall Guard Parity

- [x] 4.1 Extract reusable preflight helpers from command-policy, secret-key reference, kubectl, and sops guards so background task commands can be checked without synthesizing fake `bash` tool calls.
- [x] 4.2 Apply those preflight checks before every background task launch and return the same reason style as foreground `bash` blocks.
- [x] 4.3 Reuse or extract secret-output redaction so model-visible background task output (`bg_task`, `bg_status`, `/bg` notifications, and follow-ups) is redacted consistently with foreground `bash` output.
- [x] 4.4 Add tests proving each blocked preflight class—command policy, secret key, kubectl, and sops—returns foreground-compatible reasons and does not spawn a sandbox process.
- [x] 4.5 Add tests proving loaded secret values in background output are redacted in `bg_task`, `bg_status`, `/bg` notifications, and follow-up messages.

## 5. Secure Log Storage

- [x] 5.1 Store background task logs under a Heimdall/Pi private runtime directory with owner-only directory permissions.
- [x] 5.2 Create log files with owner read/write-only permissions and non-guessable filename components.
- [x] 5.3 Ensure caller-supplied `cwd`, `title`, command text, id, or PID cannot select an arbitrary log path.
- [x] 5.4 Delete cleared finished tasks' log files on a best-effort basis when `bg_task action=clear` removes those tasks.
- [x] 5.5 Delete tracked task log files on a best-effort basis during session shutdown after terminating running tasks.

## 6. Tests and Documentation

- [x] 6.1 Add tests for independent extension registration: core-only does not register background surfaces; background extension enabled registers `bg_task`, `bg_status`, `/bg`, and the shortcut without an additional config flag.
- [x] 6.2 Add tests for `bg_task` spawn/list/log/stop/clear behavior, missing command errors, unknown id/PID errors, stopping already-finished tasks, output wakeups, and `notifyPattern` matching.
- [x] 6.3 Add tests for `bg_status` list/log/stop compatibility, missing PID errors, and unknown PID errors.
- [x] 6.4 Add tests proving background task spawn uses `heimdall-sandbox exec --policy -` with generated policy JSON and never raw local shell spawn.
- [x] 6.5 Add tests for fail-closed behavior when sandboxing is disabled, `--no-sandbox` is active, the binary is unavailable, policy generation/config validation fails, or cwd is missing.
- [x] 6.6 Add tests for completion/output follow-up messages, log tail truncation, secure log storage, log cleanup, and session shutdown cleanup.
- [x] 6.7 Update `README.md` with enable/disable examples for the optional Heimdall background-task extension and instructions to disable `@ifi/pi-background-tasks` when using Heimdall's safe replacement.
- [x] 6.8 Run `npm run typecheck`, `npm test`, and `npm run check:pack`.
