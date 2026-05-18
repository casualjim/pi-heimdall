## ADDED Requirements

### Requirement: oh-pi-compatible timeout backgrounding
Heimdall SHALL provide `oh-pi`-compatible background behavior from its existing `bash` tool: a command that is still running after the effective timeout SHALL be kept running as a background process and the original tool call SHALL return PID and log information.

#### Scenario: Command exceeds default threshold
- **WHEN** a `bash` command is still running after 10 seconds and no explicit timeout was provided
- **THEN** Heimdall SHALL move the command to the background and return a response containing the PID, log file path, stop hint, output preview, and notification notice

#### Scenario: Explicit timeout overrides default threshold
- **WHEN** a `bash` command provides an explicit timeout value
- **THEN** Heimdall SHALL use that timeout value as the backgrounding threshold instead of the 10 second default

#### Scenario: Command exits before threshold
- **WHEN** a `bash` command exits before the effective timeout threshold
- **THEN** Heimdall SHALL return the command output and exit information without adding it to the background process list

### Requirement: Sandboxed background launch
Heimdall SHALL launch backgrounded commands through the same sandbox decision path as foreground `bash` commands.

#### Scenario: Sandbox active
- **WHEN** sandboxing is active and a `bash` command is backgrounded
- **THEN** Heimdall SHALL keep the process running under the same sandbox launch path used by foreground `bash` commands

#### Scenario: Sandbox unavailable or disabled
- **WHEN** sandboxing is unavailable or disabled and a `bash` command is backgrounded
- **THEN** Heimdall SHALL use the local shell fallback path for the background process

### Requirement: Background completion notification
Heimdall SHALL notify the agent when a backgrounded command finishes.

#### Scenario: Background process finishes
- **WHEN** a background process exits after the original `bash` tool call returned
- **THEN** Heimdall SHALL update the process status and send a follow-up completion message containing the PID, exit status, command, and output tail

#### Scenario: Background process output grows large
- **WHEN** a background process produces more output than the completion message tail limit
- **THEN** Heimdall SHALL include a truncated output tail in the completion message and keep the full output in the log file

### Requirement: bg_status compatibility
Heimdall SHALL provide a `bg_status` tool compatible with `oh-pi`'s `list`, `log`, and `stop` actions for backgrounded commands.

#### Scenario: List background processes
- **WHEN** `bg_status` is called with action `list`
- **THEN** Heimdall SHALL return all tracked background processes with PID, running/stopped status, exit code when available, log file path, and command

#### Scenario: Read background log
- **WHEN** `bg_status` is called with action `log` and a tracked PID
- **THEN** Heimdall SHALL return the log contents using the same tail/truncation behavior as the `oh-pi` plugin

#### Scenario: Stop background process
- **WHEN** `bg_status` is called with action `stop` and a tracked running PID
- **THEN** Heimdall SHALL terminate the background process, remove it from the active map, and return a termination message

#### Scenario: Missing PID for PID action
- **WHEN** `bg_status` is called with action `log` or `stop` without a PID
- **THEN** Heimdall SHALL return an error result explaining that PID is required

### Requirement: Session cleanup
Heimdall SHALL clean up tracked background processes during session shutdown.

#### Scenario: Session shuts down with running process
- **WHEN** pi emits session shutdown while a tracked background process is still running
- **THEN** Heimdall SHALL attempt to terminate the process and clear the background process map

#### Scenario: Session shuts down after process finished
- **WHEN** pi emits session shutdown after a tracked process has already finished
- **THEN** Heimdall SHALL clear the background process map without reporting an error
