## Purpose

Define Heimdall configuration behavior so recommended defaults are transparent, overrideable, and visible in files rather than hidden runtime enforcement.

## Requirements

### Requirement: Generated transparent default config
Heimdall SHALL maintain a generated user-level default config file that makes recommended defaults visible without making them user-owned.

#### Scenario: Default config is generated
- **WHEN** Heimdall starts and the Pi agent directory is available
- **THEN** Heimdall SHALL ensure `~/.pi/agent/heimdall.default.jsonc` contains the current recommended default config
- **AND** the generated file SHALL include comments stating that it is generated, may be overwritten, and exists for transparency

#### Scenario: Sandbox remains default off
- **WHEN** Heimdall generates the default config
- **THEN** the generated config SHALL set `sandbox.enabled` to `false`
- **AND** the generated config SHALL include the recommended private-path entries under `sandbox.filesystem.deny`

### Requirement: JSONC and JSON user/project config loading
Heimdall SHALL support both JSONC and JSON config files for user and project config levels while generated defaults use JSONC only.

#### Scenario: JSONC config is loaded
- **WHEN** a user or project Heimdall config file uses the `.jsonc` extension
- **THEN** Heimdall SHALL parse it as JSONC, including comments and trailing commas

#### Scenario: Legacy JSON config is loaded
- **WHEN** a user or project Heimdall config file uses the `.json` extension
- **THEN** Heimdall SHALL continue loading it for backward compatibility

#### Scenario: JSONC is preferred over JSON at the same level
- **WHEN** both `.jsonc` and `.json` user or project config files exist for the same config level
- **THEN** Heimdall SHALL load the `.jsonc` file for that level
- **AND** Heimdall SHALL NOT merge the `.json` file from that same level

### Requirement: Config precedence
Heimdall SHALL assemble effective config by applying generated defaults first, user config second, and project config last.

#### Scenario: Default config provides fallback values
- **WHEN** neither user config nor project config defines a sandbox field that is present in `heimdall.default.jsonc`
- **THEN** the effective config SHALL use the value from `heimdall.default.jsonc`

#### Scenario: User config overrides generated defaults
- **WHEN** user config defines a sandbox field that is also present in `heimdall.default.jsonc`
- **THEN** the effective config SHALL prefer the user config value according to Heimdall merge semantics

#### Scenario: Project config overrides user config
- **WHEN** project config defines a sandbox field that is also present in user config
- **THEN** the effective config SHALL prefer the project config value according to Heimdall merge semantics

### Requirement: Default filesystem deny opt-out
Heimdall SHALL allow user or project config to disable only the generated recommended filesystem deny list.

#### Scenario: Default filesystem deny is enabled
- **WHEN** the effective config does not set `sandbox.useDefaultFilesystemDeny` to `false`
- **THEN** Heimdall SHALL include generated recommended private-path deny entries in the effective sandbox filesystem deny policy

#### Scenario: Default filesystem deny is disabled
- **WHEN** user config or project config sets `sandbox.useDefaultFilesystemDeny` to `false`
- **THEN** Heimdall SHALL exclude generated recommended private-path deny entries from the effective sandbox filesystem deny policy
- **AND** Heimdall SHALL continue applying explicitly configured `sandbox.filesystem.deny` entries from user config, project config, and `.heimdall-deny` fragments

### Requirement: No hidden private-path enforcement
Heimdall SHALL NOT enforce a hardcoded private-path deny list outside the visible config and fragment inputs.

#### Scenario: Runtime policy is built from effective config
- **WHEN** Heimdall normalizes sandbox config or builds a native sandbox policy
- **THEN** Heimdall SHALL use the merged effective config as the source of sandbox filesystem deny entries
- **AND** Heimdall SHALL NOT append an additional hardcoded private-path deny list in `sandbox-guard.ts`

#### Scenario: Host-tool checks use explicit policy inputs
- **WHEN** Heimdall evaluates host-side file tool access under sandbox filesystem rules
- **THEN** Heimdall SHALL use effective config and explicit fragment files such as `.heimdall-deny`
- **AND** Heimdall SHALL NOT apply an invisible built-in private-path deny list
