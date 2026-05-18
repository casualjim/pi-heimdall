## ADDED Requirements

### Requirement: Native sandbox policy schema
Pi Heimdall SHALL use `sandbox.enabled` in `.pi/heimdall.json` as the Pi-side sandbox toggle and SHALL use the native `heimdall-sandbox` policy schema for all other sandbox configuration fields.

#### Scenario: Native sandbox fields are configured
- **WHEN** `.pi/heimdall.json` contains `sandbox.network`, `sandbox.proc`, `sandbox.env`, or `sandbox.filesystem`
- **THEN** Pi Heimdall SHALL interpret those fields as `heimdall-sandbox` JSON policy fields
- **AND** Pi Heimdall SHALL NOT require or translate the previous POC `paths`/`mode` schema

#### Scenario: Disabled toggle is local to Pi Heimdall
- **WHEN** `.pi/heimdall.json` contains `sandbox.enabled: false`
- **THEN** Pi Heimdall SHALL disable sandbox delegation for bash commands
- **AND** Pi Heimdall SHALL NOT pass `enabled: false` to `heimdall-sandbox`

#### Scenario: Enabled toggle is omitted from generated policy
- **WHEN** `.pi/heimdall.json` contains `sandbox.enabled: true`
- **THEN** Pi Heimdall MAY omit `enabled` from the generated native policy
- **AND** sandbox behavior SHALL be driven by the remaining native policy fields and runtime execution fields

### Requirement: Per-command policy generation
Pi Heimdall SHALL generate a complete native sandbox policy for each sandboxed bash invocation by combining configured sandbox fields with runtime execution fields.

#### Scenario: Bash command is sandboxed
- **WHEN** sandboxing is active and the `bash` tool executes command text
- **THEN** Pi Heimdall SHALL generate a JSON policy whose `command` is `['bash', '-c', <command text>]`
- **AND** the policy SHALL include the execution `cwd`
- **AND** the policy SHALL include `stdio: 'piped'`

#### Scenario: Configured policy fields are preserved
- **WHEN** `.pi/heimdall.json` configures native `sandbox.network`, `sandbox.proc`, `sandbox.env`, or `sandbox.filesystem`
- **THEN** Pi Heimdall SHALL copy those fields into the generated policy without applying POC path or environment semantics

### Requirement: Native sandbox execution
Pi Heimdall SHALL execute sandboxed bash commands by delegating to the installed `heimdall-sandbox` binary.

#### Scenario: Sandbox command is launched
- **WHEN** a generated policy is ready
- **THEN** Pi Heimdall SHALL spawn `heimdall-sandbox exec --policy -`
- **AND** Pi Heimdall SHALL write the generated policy JSON to the native process stdin

#### Scenario: Native stdout and stderr stream through Pi
- **WHEN** the native sandbox process writes stdout or stderr
- **THEN** Pi Heimdall SHALL forward that data through the Pi bash tool update stream

#### Scenario: Native process exits
- **WHEN** `heimdall-sandbox` exits
- **THEN** Pi Heimdall SHALL return the native exit code through the bash operation result

#### Scenario: Native launch fails while sandbox is requested
- **WHEN** sandboxing is enabled but `heimdall-sandbox` cannot be launched
- **THEN** Pi Heimdall SHALL surface a clear error instead of silently executing the command unsandboxed

### Requirement: POC sandbox behavior removal
Pi Heimdall SHALL stop owning sandbox policy behavior that is now native to `heimdall-sandbox`.

#### Scenario: Bubblewrap args are no longer built in TypeScript
- **WHEN** sandboxing is active
- **THEN** Pi Heimdall SHALL NOT construct bubblewrap arguments directly

#### Scenario: Old path schema is not supported
- **WHEN** `.pi/heimdall.json` uses `sandbox.paths` with `mode` entries
- **THEN** Pi Heimdall SHALL NOT treat that shape as the supported sandbox policy schema

#### Scenario: Old environment extensions are not supported
- **WHEN** `.pi/heimdall.json` uses sandbox env globs or `sandbox.env.set`
- **THEN** Pi Heimdall SHALL NOT apply the previous TypeScript-only env filtering behavior

#### Scenario: Platform support is native-owned
- **WHEN** sandboxing is active
- **THEN** Pi Heimdall SHALL let `heimdall-sandbox` determine whether the current platform supports the requested isolation
