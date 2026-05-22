## Why

Heimdall currently applies a hardcoded sandbox filesystem deny list from TypeScript, which makes part of the effective security policy invisible to users and difficult to adjust. Moving recommended defaults into generated JSONC config keeps sandbox defaults transparent, editable, and updateable while preserving sandbox-off-by-default behavior.

## What Changes

- Generate a transparent `~/.pi/agent/heimdall.default.jsonc` config containing recommended defaults, including the current private-path filesystem deny list.
- Support user and project Heimdall config files as JSONC as well as JSON, with `.jsonc` preferred and `.json` retained for compatibility.
- Load config from generated defaults, user config, and project config in precedence order, with project config overriding user config.
- Add `sandbox.useDefaultFilesystemDeny` so users or projects can disable the generated recommended filesystem deny list explicitly.
- Remove hidden runtime use of a hardcoded private-path deny list; runtime enforcement should use only merged config plus explicit fragment files such as `.heimdall-deny`.
- Document that generated default config may be overwritten and exists for transparency, while user/project config remains user-owned.

## Capabilities

### New Capabilities

- `transparent-heimdall-config`: JSONC-based Heimdall config loading with visible generated defaults, JSON compatibility, and explicit control over default sandbox filesystem denies.

### Modified Capabilities

- None.

## Impact

- Affected code: `extensions/heimdall.ts`, `guards/sandbox-guard.ts`, `guards/types.ts`, config loading/merge helpers, and tests.
- Affected files: new generated user-level default config path `~/.pi/agent/heimdall.default.jsonc`; preferred user/project config paths `heimdall.jsonc` with legacy `heimdall.json` support.
- Affected docs: README configuration and sandbox sections should describe JSONC support, load precedence, generated defaults, and `sandbox.useDefaultFilesystemDeny`.
- Compatibility: existing `heimdall.json` files continue to load; sandbox remains disabled unless explicitly enabled.
