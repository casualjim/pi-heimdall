# Guards

## Responsibility
Pi-facing enforcement adapters for tool activity. Guard modules block unsafe `tool_call`s, redact sensitive `tool_result`s, and wire Pi hooks to lower-level sandbox helpers when sandboxing is enabled.
## Dependencies
- **Pi Extension API**: Shapes hooks, tool predicates, notifications, and wrapped-tool overrides.
- **`shell-quote`**: Makes command-policy checks shell-aware.
- **`../types.js`**: Supplies shared config contracts for guard modules.
- **`../sandbox/*.js`**: Supplies sandbox policy normalization, launch/runtime, and filesystem checks.
## Consumers
- **`extensions/heimdall.ts`**: Registers runtime guards.
- **`lib/preflight.ts`**: Reuses pure guard detection helpers for detached work.
## Module Structure
```text
lib/guards/
├── command-policy-guard.ts
├── env-protect.ts
├── kubectl-secret-guard.ts
├── sandbox-guard.ts      # Pi-facing sandbox wiring; delegates to ../sandbox/
├── secret-guard.ts
└── sops-secret-guard.ts
```
## Register-Once Guard Module (closure state, explicit opt-out)
```ts
export function registerSecretGuard(pi: ExtensionAPI, disabled: ReadonlySet<string>): void {
  let secretNames: RegExp | null = null;
  let secretValues: Record<string, string> = {};

  pi.on("session_start", async (_event, ctx) => {
    if (!disabled.has("secret-guard")) ({ secretNames, secretValues } = await loadSecretState(ctx.cwd));
  });

  pi.on("tool_call", async (event) =>
    disabled.has("secret-guard") || !isToolCallEventType("bash", event)
      ? undefined
      : findSecretReference(event.input.command, secretNames)
        ? { block: true, reason: "Blocked: command references a protected secret." }
        : undefined,
  );
}
```
## Tokenized Command Policy Boundary (prefix rules, not regexes)
```ts
type CommandPolicy = { name: string; blocked: string[]; message: string };

function checkCommand(command: string, policies: CommandPolicy[]): CommandPolicy | null {
  for (const segment of splitSegments(parse(command))) {
    const effective = stripEnvAndWrappers(segment); // sudo/env/bash -c aware
    for (const policy of policies) if (policy.blocked.every((token, i) => effective[i] === token)) return policy;
  }
  return null;
}
```
## Two-Phase Secret Protection (preflight block + postflight redaction)
```ts
pi.on("tool_call", async (event) =>
  !isToolCallEventType("bash", event) ? undefined :
  mentionsProtectedSecret(event.input.command, secretNames)
    ? { block: true, reason: "Blocked: command references a protected secret." }
    : undefined,
);

pi.on("tool_result", async (event) =>
  !isBashToolResult(event) ? undefined : {
    content: event.content.map((part) => part.type === "text"
      ? { ...part, text: redactOutput(part.text, secretValues) }
      : part),
  },
);
```
## Sandboxed Bash Override + Host Tool Mediation (adapter over sandbox helpers)
```ts
export function registerSandboxGuard(pi: ExtensionAPI, getConfig: () => HeimdallConfig) {
  let sandbox: NormalizedSandboxConfig | null = null;
  pi.on("session_start", async (_event, ctx) => {
    sandbox = normalizeSandboxConfig(getConfig().sandbox, ctx.cwd);
  });

  pi.registerTool({
    ...createBashTool(process.cwd()),
    label: "bash (sandboxed)",
    async execute(id, params, signal, onUpdate) {
      const tool = sandbox
        ? createBashTool(process.cwd(), { operations: createSandboxedBashOps(sandbox, process.cwd()) })
        : createBashTool(process.cwd());
      return tool.execute(id, params, signal, onUpdate);
    },
  });

  pi.on("tool_call", async (event, ctx) => sandbox && isDenied(sandbox.policy.filesystem, ctx.cwd, event.input.path)
    ? { block: true, reason: "Blocked by sandbox filesystem policy." }
    : undefined);
}
```

## Architectural Boundaries
- **NO self-registration**: `extensions/heimdall.ts` is the only composition root.
- **NO classes/inheritance**: guards are plain modules with closure state and exported helpers.
- **NO host-tool trust when sandboxing is active**: `read`/`write`/`edit` are checked separately because native sandboxing only wraps `bash`.
- **NO shared type/runtime ownership here**: config contracts live in `lib/`; sandbox mechanics live in `lib/sandbox/`.
- **NO compatibility shims here**: guard-specific helpers stay beside guards; shared helpers live one level up in `lib/` or under `lib/sandbox/`.

<important if="you are adding a new simple opt-out guard">
## Adding a New Simple Opt-Out Guard
1. Create `lib/guards/<name>.ts` with `register<Name>Guard(pi, disabledSet)`.
2. Filter to the exact tool/event you intend to protect.
3. Keep detection in a pure helper and return `undefined` for allow, `{ block: true, reason }` for deny.
4. Add the guard ID to `lib/types.ts`, `lib/heimdall-config.ts`, and `extensions/heimdall.ts`.
5. Document the disable key and extend `lib/preflight.ts` if detached background tasks must honor it.
</important>

<important if="you are adding a new stateful or config-driven guard">
## Adding a New Stateful Guard
1. Add any new config contracts to `lib/types.ts` and/or `lib/sandbox/types.ts`.
2. Load and precompute session state in `pi.on("session_start", ...)`, not on every tool call.
3. Cache derived structures (regexes, token arrays, path matchers), not raw input only.
4. If the guard protects output as well as intent, pair `tool_call` enforcement with `tool_result` redaction.
</important>
