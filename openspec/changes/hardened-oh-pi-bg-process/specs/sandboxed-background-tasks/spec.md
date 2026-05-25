## ADDED Requirements

### Requirement: Optional same-package background task extension
Heimdall SHALL provide sandboxed background task support as a separate optional extension resource in the `@casualjim/pi-heimdall` package.

#### Scenario: Core Heimdall without background tasks
- **WHEN** a user enables only the core Heimdall extension
- **THEN** Heimdall SHALL NOT register `bg_task`, `bg_status`, `/bg`, or the background task shortcut

#### Scenario: Background task extension enabled
- **WHEN** a user enables Heimdall's background-task extension resource
- **THEN** Heimdall SHALL register the drop-in background task surfaces `bg_task`, `bg_status`, `/bg`, and `Ctrl+Shift+B`

#### Scenario: No second config gate required
- **WHEN** Heimdall's background-task extension resource is enabled
- **THEN** Heimdall SHALL register the background-task surfaces without requiring an additional `backgroundTasks.enabled` config flag

#### Scenario: Background task extension disabled
- **WHEN** a user disables Heimdall's background-task extension resource while keeping the core Heimdall extension enabled
- **THEN** Heimdall SHALL keep the core guards and sandboxed `bash` behavior active without registering background-task surfaces

### Requirement: Drop-in `@ifi/pi-background-tasks` task surface
Heimdall's background-task extension SHALL provide the same public task-management names and compatible behavior expected from `@ifi/pi-background-tasks` version `0.5.1`, except for documented safety deviations around sandboxed launch, guard preflight, output redaction, and secure log storage.

#### Scenario: Spawn explicit background task
- **WHEN** `bg_task` is called with action `spawn` and a non-empty shell command
- **THEN** Heimdall SHALL start a tracked background task, return the task id, PID, cwd, log file path, expiry/wakeup information where applicable, and task details

#### Scenario: Missing spawn command
- **WHEN** `bg_task` is called with action `spawn` without a non-empty command
- **THEN** Heimdall SHALL return an error result
- **AND** Heimdall SHALL NOT start a process

#### Scenario: List tasks through `bg_task`
- **WHEN** `bg_task` is called with action `list`
- **THEN** Heimdall SHALL return tracked tasks with id, status, PID, command, and recent activity information

#### Scenario: Inspect task log through `bg_task`
- **WHEN** `bg_task` is called with action `log` and a tracked id or PID
- **THEN** Heimdall SHALL return a bounded tail of the task output

#### Scenario: Unknown task for id/PID action
- **WHEN** `bg_task` is called with action `log` or `stop` and no tracked task matches the supplied id or PID
- **THEN** Heimdall SHALL return an error result explaining that no background task matched

#### Scenario: Stop task through `bg_task`
- **WHEN** `bg_task` is called with action `stop` and a tracked running id or PID
- **THEN** Heimdall SHALL terminate the sandboxed background process and return the updated task status

#### Scenario: Stop already-finished task through `bg_task`
- **WHEN** `bg_task` is called with action `stop` and the tracked task is already completed, failed, or stopped
- **THEN** Heimdall SHALL return a message describing the existing task status
- **AND** Heimdall SHALL NOT attempt a new process termination

#### Scenario: Clear finished tasks
- **WHEN** `bg_task` is called with action `clear`
- **THEN** Heimdall SHALL remove finished tasks from the in-memory task list without stopping running tasks
- **AND** Heimdall SHALL delete log files for the cleared tasks on a best-effort basis

#### Scenario: Output wakeups default on
- **WHEN** a background task is spawned without specifying `reactToOutput`
- **THEN** Heimdall SHALL treat output wakeups as enabled by default

#### Scenario: Output wakeups respect notify pattern
- **WHEN** a background task is spawned with a `notifyPattern`
- **THEN** Heimdall SHALL send output follow-ups only for output matching the substring or `/regex/flags` pattern

#### Scenario: Manage tasks through `/bg`
- **WHEN** a user invokes `/bg`, `/bg run <command>`, `/bg watch <id>`, `/bg watch --follow <id>`, `/bg stop <id>`, or `/bg clear`
- **THEN** Heimdall SHALL provide the corresponding task dashboard, spawn, watch, stop, and clear behavior

### Requirement: `bg_status` compatibility
Heimdall SHALL provide `bg_status` compatibility for PID-oriented background process management.

#### Scenario: List background processes
- **WHEN** `bg_status` is called with action `list`
- **THEN** Heimdall SHALL return all tracked background tasks with PID, running/stopped status, exit code when available, log file path, and command

#### Scenario: Read background log
- **WHEN** `bg_status` is called with action `log` and a tracked PID
- **THEN** Heimdall SHALL return the log contents using bounded tail/truncation behavior

#### Scenario: Stop background process
- **WHEN** `bg_status` is called with action `stop` and a tracked running PID
- **THEN** Heimdall SHALL terminate the sandboxed background process and return a termination message

#### Scenario: Missing PID for PID action
- **WHEN** `bg_status` is called with action `log` or `stop` without a PID
- **THEN** Heimdall SHALL return an error result explaining that PID is required

#### Scenario: Unknown PID for PID action
- **WHEN** `bg_status` is called with action `log` or `stop` and no tracked task matches the supplied PID
- **THEN** Heimdall SHALL return an error result explaining that no background task matched that PID

### Requirement: Sandboxed-only launch
Heimdall SHALL launch every background task through the native Heimdall sandbox runtime and SHALL NOT provide an unsandboxed fallback.

#### Scenario: Sandbox active
- **WHEN** Heimdall sandboxing is active and a background task is spawned
- **THEN** Heimdall SHALL launch the command with `heimdall-sandbox exec --policy -`
- **AND** Heimdall SHALL send a generated policy containing the task cwd, `bash -c` command argv, configured sandbox policy fields, and piped stdio

#### Scenario: Sandbox disabled
- **WHEN** Heimdall sandboxing is disabled for the session or config
- **THEN** background task spawn SHALL fail with an error
- **AND** Heimdall SHALL NOT start a local unsandboxed process

#### Scenario: Sandbox binary unavailable
- **WHEN** the `heimdall-sandbox` binary cannot be resolved or launched
- **THEN** background task spawn SHALL fail with an error
- **AND** Heimdall SHALL NOT start a local unsandboxed process

#### Scenario: Sandbox policy generation fails
- **WHEN** the effective sandbox policy cannot be generated or validated for the requested background task
- **THEN** background task spawn SHALL fail with an error
- **AND** Heimdall SHALL NOT start any process

#### Scenario: Working directory missing
- **WHEN** a background task specifies a cwd that does not exist
- **THEN** background task spawn SHALL fail with an error
- **AND** Heimdall SHALL NOT start a process

### Requirement: Foreground bash non-regression
Heimdall's background-task extension SHALL NOT change ordinary foreground `bash` behavior.

#### Scenario: Ordinary bash remains foreground
- **WHEN** Heimdall's background-task extension is enabled and a user invokes the ordinary `bash` tool
- **THEN** Heimdall SHALL use the existing foreground `bash` behavior
- **AND** Heimdall SHALL NOT convert timed-out or long-running `bash` commands into background tasks
- **AND** Heimdall SHALL NOT change existing foreground `bash` timeout, guard, or sandbox semantics

### Requirement: Background commands honor Heimdall command protections
Heimdall SHALL apply relevant command preflight protections to background task commands before launching them.

#### Scenario: Command violates command policy
- **WHEN** a background task command violates a configured Heimdall command policy
- **THEN** Heimdall SHALL block the task before launch and return the same policy reason style as foreground `bash`

#### Scenario: Command references protected secret key
- **WHEN** a background task command references a secret key protected by Heimdall's secret guard
- **THEN** Heimdall SHALL block the task before launch and return a secret-guard reason

#### Scenario: Command matches risky kubectl or sops patterns
- **WHEN** a background task command matches Heimdall's risky kubectl or sops decrypt protections
- **THEN** Heimdall SHALL block the task before launch and return the corresponding guard reason

### Requirement: Secure background log storage
Heimdall SHALL store background task logs in private Heimdall-owned storage rather than caller-controlled or public temp paths.

#### Scenario: Log file created
- **WHEN** Heimdall creates a log file for a background task
- **THEN** the log SHALL be created under a Heimdall/Pi private runtime directory
- **AND** the containing directory SHALL use permissions equivalent to owner-only access
- **AND** the log file SHALL use permissions equivalent to owner read/write only
- **AND** the filename SHALL include a non-guessable component

#### Scenario: Caller supplies cwd or title
- **WHEN** a background task includes caller-supplied `cwd`, `title`, or command text
- **THEN** Heimdall SHALL NOT use those values as a caller-controlled log path

#### Scenario: Cleared task log cleanup
- **WHEN** `bg_task` clears finished tasks
- **THEN** Heimdall SHALL make a best-effort attempt to delete the cleared tasks' log files

#### Scenario: Shutdown log cleanup
- **WHEN** Pi emits session shutdown
- **THEN** Heimdall SHALL make a best-effort attempt to delete tracked background task log files after stopping running tasks

### Requirement: Background output and notifications
Heimdall SHALL track sandboxed background task output, expose bounded log tails, and notify the agent when watched tasks produce output or exit.

#### Scenario: Background task produces output
- **WHEN** a running background task writes stdout or stderr
- **THEN** Heimdall SHALL append the output to the task log and update the task output buffer

#### Scenario: Background task exits
- **WHEN** a background task exits after the original `bg_task` or `/bg run` call returned
- **THEN** Heimdall SHALL update the task status and send a follow-up completion message containing the task id, PID, exit status, command, log path, and bounded output tail

#### Scenario: Background task output grows large
- **WHEN** a background task produces more output than the response tail limit
- **THEN** Heimdall SHALL include a truncated output tail in tool responses and follow-up messages while keeping the full output in the log file while the task is tracked

#### Scenario: Tool-visible output contains redacted secret material
- **WHEN** Heimdall has loaded secret values and background task tool-visible output contains material that foreground `bash` output would redact
- **THEN** Heimdall SHALL redact that material from `bg_task`, `bg_status`, `/bg` notifications, and follow-up messages

### Requirement: Session cleanup
Heimdall SHALL clean up tracked sandboxed background tasks during session shutdown.

#### Scenario: Session shuts down with running task
- **WHEN** Pi emits session shutdown while a tracked background task is still running
- **THEN** Heimdall SHALL attempt to terminate the sandboxed process group and clear the background task map

#### Scenario: Session shuts down after task finished
- **WHEN** Pi emits session shutdown after a tracked background task has already finished
- **THEN** Heimdall SHALL clear the background task map without reporting an error
