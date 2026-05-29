# Sandbox

## Responsibility
Sandbox helper layer for native `heimdall-sandbox` integration. It owns sandbox config normalization, policy generation, binary resolution, process launch/termination, and host-tool filesystem matching. It does **not** register Pi hooks directly.

## Dependencies
- **Native `heimdall-sandbox` contract**: Defines the execution policy JSON passed to the sandbox runtime.
- **Pi bash operations types**: Used only by runtime helpers that create sandbox-backed bash operations.
- **`ignore`**: Implements gitignore-style deny/write fragment matching.
- **Node fs/path/os/child_process**: Supports config migration, fragment loading, path resolution, and process lifecycle.

## Consumers
- **`lib/guards/sandbox-guard.ts`**: Wires sandbox helpers into Pi session lifecycle, tool overrides, and host-tool mediation.
- **`lib/background-tasks/extension.ts`**: Reuses sandbox normalization and launch/runtime helpers for detached execution.
- **`lib/heimdall-config.ts`**: Reuses the default private-path catalog for generated defaults.

## Module Structure
```text
lib/sandbox/
├── config.ts                # normalize config, migrate legacy paths, build native policy
├── runtime.ts               # binary discovery, launch, termination, bash operations
├── filesystem-policy.ts     # .heimdall-deny/.heimdall-write + path matching
├── default-private-paths.ts # generated default deny catalog
└── types.ts                 # sandbox policy/config contracts
```

## Normalize Pi-local Config into Native Policy Fragment
```ts
export function normalizeSandboxConfig(config?: SandboxConfig): NormalizedSandboxConfig {
  return {
    enabled: config?.enabled ?? false,
    binaryPath: config?.binaryPath,
    policy: {
      network: config?.network,
      proc: config?.proc,
      env: config?.env,
      filesystem: config?.filesystem ?? {},
    },
  };
}
```

## Launch Through the Native Runtime Only
```ts
export async function launchSandboxProcess(config: NormalizedSandboxConfig, command: string, options: { cwd: string }) {
  const policy = buildSandboxPolicy(config, options.cwd, command);
  const child = spawn(binaryPath, ["exec", "--policy", "-"], {
    cwd: options.cwd,
    detached: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
  child.stdin.end(`${JSON.stringify(policy)}\n`);
  return { child, policy };
}
```

## Host-Tool Filesystem Mediation Reuses Fragment Files
```ts
export function isDenied(filesystem: SandboxFilesystemPolicy | undefined, cwd: string, rawPath: string): boolean {
  const denyPatterns = [...(filesystem?.deny ?? []), ...loadFragmentFile(cwd, ".heimdall-deny")];
  const target = resolve(cwd, untildify(rawPath));
  return matchesAbsolutePrefix(target, denyPatterns, cwd) || matchesGitignorePatterns(target, denyPatterns, cwd);
}
```

## Architectural Boundaries
- **NO Pi hook registration**: event wiring stays in `lib/guards/sandbox-guard.ts`.
- **NO config loading**: sandbox helpers consume already-materialized config snapshots from `lib/`.
- **NO duplicated policy enforcement in background tasks**: detached work reuses these helpers instead of spawning directly.

<important if="you are extending sandbox policy or runtime behavior">
## Extending Sandbox Policy or Runtime Behavior
1. Add policy/config contracts in `lib/sandbox/types.ts`.
2. Normalize Pi-local config in `lib/sandbox/config.ts`; do not leak Pi-only flags into the native policy JSON.
3. Keep native process launch and termination inside `lib/sandbox/runtime.ts`.
4. If host-tool path mediation changes, update `lib/sandbox/filesystem-policy.ts` and the corresponding `tests/sandbox-guard.test.ts` cases.
5. If generated defaults change, update `lib/sandbox/default-private-paths.ts`, `lib/heimdall-config.ts`, and `tests/heimdall-config.test.ts` together.
</important>
