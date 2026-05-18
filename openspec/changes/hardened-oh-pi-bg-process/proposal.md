## Why

Heimdall conflicts with `oh-pi`'s `bg-process.ts` because both packages register a custom `bash` tool. Users should be able to disable the conflicting `oh-pi` plugin while keeping the same long-running command workflow through Heimdall's sandboxed `bash` implementation.

## What Changes

- Port `oh-pi`'s background-process behavior into Heimdall's existing `bash` override.
- Keep one Heimdall-owned `bash` tool that runs commands through Heimdall's sandbox launch path when sandboxing is active and through the existing local fallback otherwise.
- Preserve `oh-pi` behavior: commands still running after the effective timeout are moved to the background, return PID/log information, and notify the agent when they finish.
- Preserve `oh-pi`'s `bg_status` management surface with `list`, `log`, and `stop` actions.
- Document that Heimdall can replace `oh-pi`'s `bg-process.ts` and that users should disable that single conflicting plugin.

## Capabilities

### New Capabilities

- `background-bash-processes`: `oh-pi`-compatible background execution for long-running `bash` commands, using Heimdall's sandbox launch path when available.

### Modified Capabilities

None.

## Impact

- Affected code: primarily `guards/sandbox-guard.ts`, plus types/tests/docs as needed.
- Affected tools: Heimdall's `bash` override and a `bg_status`-compatible tool owned by Heimdall.
- Affected docs: `README.md` troubleshooting and usage notes for replacing `oh-pi`'s `bg-process.ts`.
- Dependencies: no new runtime dependency expected; reuse Node.js process and filesystem APIs.
