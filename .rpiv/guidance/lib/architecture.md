# Lib

## Responsibility
Internal config and shared-contract layer. It generates visible defaults, discovers user/project config files, parses JSONC/JSON, owns shared config contracts, and exposes the merged `HeimdallConfig` plus preflight reuse helpers that runtime layers consume at `session_start`.

## Dependencies
- **`jsonc-parser`**: Makes JSONC the preferred authoring format and defines the tolerant parse behavior.
- **`./types.js`**: Supplies the shared config contracts owned by this layer.
- **`./sandbox/default-private-paths.js`**: Supplies the generated default deny catalog.
- **Node fs/path**: Keeps config loading synchronous and startup/session-bound.

## Consumers
- **`extensions/heimdall.ts`**: Loads effective config for the core guard extension and derives active/disabled counts.
- **`lib/background-tasks/extension.ts`**: Loads the same effective config snapshot for detached execution.
- **`lib/guards/*.ts`**: Import shared config contracts from `lib/types.ts`.
- **`lib/sandbox/*.ts`**: Import sandbox policy contracts from `lib/sandbox/types.ts`.

## Module Structure
```text
lib/
├── background-tasks/
├── guards/
├── sandbox/
├── heimdall-config.ts  # ID registry, tolerant file loading, generated defaults, layered merge facade
├── preflight.ts        # detached/background reuse of guard detection + redaction
└── types.ts            # shared Heimdall config and opt-out guard contracts
```

## Tolerant Layered Config Facade (JSONC-first, snapshot-based)
```ts
function pickConfigPath(dir: string, basename: string): string | undefined {
  return existsSync(join(dir, `${basename}.jsonc`))
    ? join(dir, `${basename}.jsonc`)    // prefer JSONC
    : existsSync(join(dir, `${basename}.json`))
      ? join(dir, `${basename}.json`)
      : undefined;
}

function loadConfigFile(path: string | undefined): Record<string, unknown> | null {
  if (!path) return null;
  const errors: ParseError[] = [];
  const parsed = parse(readFileSync(path, "utf8"), errors, { allowTrailingComma: true });
  return errors.length === 0 && parsed && typeof parsed === "object" ? parsed as Record<string, unknown> : null;
}

export function loadEffectiveConfig(agentDir: string, cwd: string) {
  return {
    config: mergeConfigLevels(
      loadConfigFile(ensureGeneratedDefaultConfig(agentDir)),
      loadConfigFile(pickConfigPath(agentDir, "heimdall")),
      loadConfigFile(pickConfigPath(join(cwd, ".pi"), "heimdall")),
    ),
  };
}
```

## Generated Defaults + Replay Merge Exception
```ts
export const OPT_OUT_GUARD_IDS = [
  "secret-guard",
  "command-policy-guard",
  "env-protect",
  "kubectl-secret-guard",
  "sops-secret-guard",
] as const;

function defaultConfigText(): string {
  const denyLines = DEFAULT_PRIVATE_PATHS.map((value) => `        ${JSON.stringify(value)}`).join(",\n");
  return `{"sandbox":{"enabled":false,"useDefaultFilesystemDeny":true,"filesystem":{"deny":[\n${denyLines}\n]}}}`;
}

export function mergeConfigLevels(defaults: Config, user: Config, project: Config): Config {
  let merged = deepMerge(deepMerge(defaults, user), project);
  if ((merged.sandbox as any)?.useDefaultFilesystemDeny === false) {
    merged = deepMerge(deepMerge(withoutGeneratedDeny(defaults), user), project); // replay merge
  }
  return merged;
}
```

## Architectural Boundaries
- **NO runtime enforcement**: `heimdall-config.ts` stops at config discovery/parsing/merging.
- **NO hot reload**: consumers reload on `session_start` and then cache a session snapshot.
- **NO sandbox runtime ownership here**: sandbox launch/process/filesystem mechanics live in `lib/sandbox/`.
- **YES shared contract ownership here**: `HeimdallConfig` and opt-out guard IDs live in `lib/types.ts`.

<important if="you are adding a new config field">
## Adding a New Config Field
1. Add the field to the current schema source in `lib/types.ts` and/or `lib/sandbox/types.ts`.
2. Decide its merge behavior: object recurse, array append, scalar override.
3. Add a generated default only if the field should be visible by default.
4. Consume it through `loadEffectiveConfig(...)`; do not add ad hoc file reads in callers.
5. Add tests for precedence across generated default, user, and project config.
</important>

<important if="you are changing generated defaults or merge semantics">
## Changing Defaults or Merge Rules
1. Update `defaultConfigText()` or the lower-level constant source of truth.
2. Keep the generated file transparent and overwrite-safe; local edits belong in user or project config.
3. If the change interacts with `useDefaultFilesystemDeny`, update the replay-merge path too.
4. Extend `tests/heimdall-config.test.ts` with behavior-level assertions, not implementation-only checks.
</important>
