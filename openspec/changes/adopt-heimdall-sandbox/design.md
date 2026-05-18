## Context

Pi Heimdall's current sandbox guard began as a TypeScript proof of concept. It owns path-prefix rules, default private path lists, environment glob filtering, synthetic file staging, and direct bubblewrap argument construction. The sibling `heimdall-sandbox` project now owns the production sandbox runtime with a documented JSON policy schema and cross-platform Linux/macOS execution behavior.

The right split is not to remove Pi config entirely. Pi Heimdall still needs an integration toggle and a way to configure sandbox behavior for Pi-launched commands. The split is to stop maintaining a second sandbox policy language and use the native `heimdall-sandbox` policy shape under `.pi/heimdall.json`.

## Goals / Non-Goals

**Goals:**

- Keep `sandbox.enabled` as a Pi-side on/off switch.
- Use the native `heimdall-sandbox` policy schema for all other `sandbox` fields.
- Delegate sandboxed bash execution to `heimdall-sandbox exec --policy -`.
- Build the policy per command by injecting runtime-only `cwd`, `command`, and `stdio` fields.
- Remove direct bubblewrap and Linux-only sandbox logic from the Pi extension.
- Preserve useful Pi integration UI/status/flag behavior.

**Non-Goals:**

- Reimplementing native policy validation in TypeScript.
- Preserving backward compatibility for the POC `paths`/`mode` schema.
- Preserving legacy sandbox fields such as `networkAccess`, `writableRoots`, `systemPaths`, `etcReal`, `etcSynthetic`, `envAllowlist`, or `extraReadPaths`.
- Adding TypeScript env glob expansion or `env.set` compatibility on top of native env behavior.
- Changing `heimdall-sandbox` itself.

## Decisions

### Treat `sandbox.enabled` as Pi-local

`enabled` remains useful in `.pi/heimdall.json` because users need to turn the integration on or off:

```json
{
  "sandbox": {
    "enabled": true
  }
}
```

When `enabled` is false or `--no-sandbox` is supplied, Pi Heimdall should not invoke the native sandbox runtime. `enabled: false` must not be forwarded into the generated native policy because `heimdall-sandbox` accepts absent/true and rejects false.

### Use native policy fields under `sandbox`

All other fields under `sandbox` should match the native policy schema accepted by `heimdall-sandbox exec --policy`:

```json
{
  "sandbox": {
    "enabled": true,
    "network": "host",
    "proc": "default",
    "env": {
      "deny": ["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"]
    },
    "filesystem": {
      "deny": ["**/.env*", "!**/.env.example"],
      "writable": ["."]
    }
  }
}
```

The old POC shape should be removed rather than translated:

```json
{
  "paths": {},
  "env": { "set": {}, "allow": ["AWS_*"], "deny": ["*_TOKEN"] },
  "networkAccess": false,
  "writableRoots": [],
  "systemPaths": [],
  "etcReal": [],
  "etcSynthetic": {},
  "extraReadPaths": []
}
```

### Generate a per-command policy

For each sandboxed bash command, Pi Heimdall should combine the configured sandbox fragment with runtime-only execution fields:

```json
{
  "network": "host",
  "proc": "default",
  "env": { "deny": ["GITHUB_TOKEN"] },
  "filesystem": { "writable": ["."] },
  "cwd": "/repo",
  "command": ["bash", "-c", "npm test"],
  "stdio": "piped"
}
```

`stdio: "piped"` lets Pi stream stdout/stderr back through its tool interface. `command` should be argv, not shell text, with `bash -c <command>` preserving current bash tool semantics.

### Let native own policy semantics

Pi Heimdall should not interpret filesystem pattern semantics beyond copying configured fields into the generated policy. Native owns:

- gitignore-style `filesystem.deny` and `filesystem.writable`
- `.heimdall-deny` and `.heimdall-write` fragment files
- `filesystem.virtual`
- exact `env.allow` and `env.deny` behavior
- network and proc policy behavior
- Linux bubblewrap and macOS Seatbelt planning
- process hardening and platform-specific environment stripping

Pi should surface native launch/validation errors clearly instead of falling back silently when sandboxing was requested.

### Keep Pi host-tool checks separate

`heimdall-sandbox` only constrains commands it executes. It cannot directly sandbox Pi host-side tools such as `read`, `write`, or `edit`. If Pi Heimdall continues to restrict those tools, that is a separate Pi integration concern and should not be confused with native command sandboxing.

A conservative first implementation can remove old POC path-policy enforcement for host tools unless a new requirement defines how native policy should be projected onto host-tool decisions.

## Risks / Trade-offs

- Existing users of the POC `paths` schema must migrate to native `filesystem` patterns.
- Native env allow/deny uses exact names, not the previous TS glob behavior.
- Host-side Pi file tools are outside the native process sandbox; preserving equivalent restrictions would require a separate design.
- Sandboxed execution now depends on finding the installed `heimdall-sandbox` binary.

## Migration Plan

1. Update types to represent the native policy fragment plus Pi-local `enabled`.
2. Replace bwrap construction with native policy generation and `heimdall-sandbox exec --policy -` launch.
3. Remove legacy/POC sandbox schema support and tests.
4. Add tests for policy generation, disabled behavior, binary launch behavior, and error surfacing.
5. Update README sandbox configuration docs to the native schema.
