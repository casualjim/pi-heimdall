## Why

`guards/sandbox-guard.ts` contains a proof-of-concept sandbox configuration model and bubblewrap adapter that duplicates policy semantics now owned by the standalone `heimdall-sandbox` runtime. This creates two sandbox languages, two execution planners, and Linux-specific logic in the Pi extension even though `heimdall-sandbox` already defines the cross-platform policy schema and platform behavior.

Pi Heimdall should keep only the Pi integration concerns: whether sandboxing is enabled for the extension, how to wrap Pi's `bash` tool, and how to pass a per-command policy to the installed native runtime.

## What Changes

- Keep `sandbox.enabled` in `.pi/heimdall.json` as the Pi-side toggle.
- Replace the POC sandbox fields under `sandbox` with the native `heimdall-sandbox` policy fields: `network`, `proc`, `env`, and `filesystem`.
- Generate a per-command JSON policy by combining configured sandbox fields with runtime `cwd`, `command`, and `stdio` fields.
- Launch sandboxed bash commands through `heimdall-sandbox exec --policy -` and send the generated policy on stdin.
- Remove TS-owned bubblewrap argument construction, legacy sandbox config translation, synthetic file staging, env glob/set behavior, and Linux-only sandbox checks.
- Preserve Pi-facing controls such as `--no-sandbox`, status/notification behavior, and clear fallback/diagnostic behavior when sandboxing is disabled or unavailable.

## Capabilities

### New Capabilities

- `sandbox-policy-delegation`: Pi Heimdall delegates sandbox execution to the native `heimdall-sandbox` policy schema and runtime.

### Modified Capabilities

None.

## Impact

- Affected code: `guards/sandbox-guard.ts`, `guards/types.ts`, sandbox tests, and README sandbox configuration docs.
- Affected config: `.pi/heimdall.json` `sandbox` keeps `enabled` but changes all other sandbox fields to the native `heimdall-sandbox` policy shape.
- Affected runtime dependency: sandboxed execution requires an installed `heimdall-sandbox` binary.
