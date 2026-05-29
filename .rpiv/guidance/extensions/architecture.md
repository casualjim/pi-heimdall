# Extensions

## Responsibility
Pi-facing composition layer. It exposes installable extension resources, owns session-scoped bootstrap state, and wires lower-level feature modules into Pi without implementing guard algorithms or background-task mechanics itself.

## Dependencies
- **Pi Extension API**: Defines the default-export installer shape and lifecycle hooks.
- **`../lib/heimdall-config.js`**: Materializes generated/default/user/project config for each session.
- **`../lib/guards/*.js`**: Supplies concrete guard registrars.
- **`../lib/background-tasks/extension.js`**: Supplies the optional background-task feature installer.

## Consumers
- **`package.json` Pi manifest**: Auto-loads `extensions/heimdall.ts` as the default package extension.
- **Pi package settings**: Optionally enable `extensions/heimdall-bg-tasks.ts` as a second resource.

## Module Structure
```text
extensions/
├── heimdall.ts           # Core composition root for config bootstrap + guard registration
└── heimdall-bg-tasks.ts  # Thin opt-in adapter for the background-task feature
```

## Thin Entrypoint Delegation (optional resource pattern)
```ts
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import registerBackgroundTasksExtension from "../lib/background-tasks/extension.js";

export default function heimdallBackgroundTasks(pi: ExtensionAPI): void {
  registerBackgroundTasksExtension(pi); // entrypoint stays tiny and stable
}
```

## Composition Root + Closure-Refreshed Session State (core pattern)
```ts
export default function heimdall(pi: ExtensionAPI): void {
  ensureGeneratedDefaultConfig(getAgentDir());

  let config: HeimdallConfig = {};
  let projectConfigPath: string | undefined;
  const disabled = new Set<string>();

  pi.on("session_start", async (_event, ctx) => {
    const effective = loadEffectiveConfig(getAgentDir(), ctx.cwd);
    config = effective.config;                    // refresh session snapshot
    projectConfigPath = effective.projectConfigPath;
    disabled.clear();
    for (const id of config.disabled ?? []) disabled.add(id);
  });

  registerSandboxGuard(pi, () => config, () => projectConfigPath);
  registerCommandPolicyGuard(pi, () => config, disabled);
  registerSecretGuard(pi, disabled);
}
```

## Architectural Boundaries
- **NO enforcement logic here**: blocking/redaction/sandbox internals stay in `lib/guards/`, `lib/sandbox/`, and `lib/background-tasks/`.
- **NO per-tool config loading**: config is reloaded on `session_start`, then read through closures/getters.
- **NO nested structure**: this directory stays flat; deeper architecture lives under `lib/`.

<important if="you are adding a new opt-out guard to the core extension">
## Adding a New Opt-Out Guard
1. Create the guard module in `lib/guards/` with a `register...` function.
2. Add its ID to `OPT_OUT_GUARD_IDS` in `lib/heimdall-config.ts` and the guard-id union in `lib/types.ts`.
3. Import and register it from `extensions/heimdall.ts`.
4. If detached background tasks must honor the same rule, extend `lib/preflight.ts` too.
</important>

<important if="you are adding a new optional extension resource">
## Adding a New Optional Extension Resource
1. Put the real implementation in `lib/<feature>/extension.ts`.
2. Keep `extensions/<feature>.ts` as a thin default-export wrapper.
3. Make duplicate registration harmless with an install symbol in the feature layer.
4. Document how users enable or disable the resource in package settings.
</important>
