# Background Tasks

## Responsibility
Optional Pi extension layer for sandboxed long-running work. It owns task lifecycle, UI surfaces, log handling, and agent wake-up messages, while delegating config loading, preflight policy checks, redaction, and native process launch to sibling helpers under `lib/`.

## Dependencies
- **Pi Extension API / TUI**: Shapes hooks, tools, commands, shortcuts, widgets, and custom renderers.
- **TypeBox**: Defines the public tool schemas for `bg_task` and `bg_status`.
- **`../preflight.js`**: Reuses foreground block/redaction rules for detached work.
- **`../sandbox/config.js` / `../sandbox/runtime.js`**: Own sandbox normalization, launch, and termination.
- **`../heimdall-config.js`**: Supplies the session-scoped merged config snapshot.

## Consumers
- **`extensions/heimdall-bg-tasks.ts`**: Thin wrapper that exposes this layer as an opt-in extension resource.
- **Pi runtime**: Consumes `bg_task`, `bg_status` (compatibility-only), `/bg`, `ctrl+shift+b`, the widget, and the custom message renderer.

## Module Structure
```text
lib/background-tasks/
├── extension.ts  # hooks, tools, command, widget, dashboard, task lifecycle
└── shared.ts     # BG_* constants, snapshot/event DTOs, log/env helpers, formatting
```

## Serializable Snapshot + Runtime Envelope (safe task boundary)
```ts
export interface BackgroundTaskSnapshot {
  id: string;
  status: "running" | "completed" | "failed" | "stopped";
  command: string;
  cwd: string;
  pid: number;
  logFile: string;
  outputBytes: number;
}

type ManagedTask = BackgroundTaskSnapshot & {
  child: ChildProcessWithoutNullStreams; // runtime-only
  output: string;                        // bounded in-memory tail
  outputTimer: ReturnType<typeof setTimeout> | null;
  matcher: ((text: string) => boolean) | null;
  closed: boolean;
};

function toSnapshot(task: ManagedTask): BackgroundTaskSnapshot {
  const { child, output, outputTimer, matcher, closed, ...snapshot } = task;
  return snapshot;
}
```

## Shared Core Operations Behind Multiple Surfaces (canonical `bg_task` API)
```ts
const tasks = new Map<string, ManagedTask>();

function resolveTask(token?: string | number) { /* id-or-pid lookup */ }
function listTasks() { /* shared formatter */ }
async function spawnTask(command: string, cwd: string) { /* shared lifecycle */ }

pi.registerTool({ name: "bg_task", async execute(_id, params) {
  if (params.action === "spawn") return spawnTask(params.command!, process.cwd());
  if (params.action === "list") return listTasks();
  return resolveTask(params.id ?? params.pid);
}});

pi.registerTool({ name: "bg_status", async execute() {
  return listTasks(); // compatibility subset only
}});

pi.registerCommand("bg", { async handler(args, ctx) { /* same helpers */ } });
pi.registerShortcut("ctrl+shift+b", { async handler(ctx) { /* opens dashboard */ } });
```

## Preflight → Sandbox Launch → Debounced Output (fail closed)
```ts
async function spawnTask(command: string, cwd: string) {
  if (!sandboxConfig || pi.getFlag("no-sandbox") === true) {
    throw new Error("Sandboxed background tasks require sandbox.enabled=true.");
  }

  const blocked = getBackgroundCommandBlockReason(command, config, disabledSet, preflightState);
  if (blocked) throw new Error(blocked); // reuse foreground guard rules

  const { child, policyJson } = await launchSandboxProcess(sandboxConfig, command, {
    cwd,
    env: createTaskShellEnv(),
  });

  child.stdout?.on("data", (chunk) => handleChunk(task, chunk));
  child.stderr?.on("data", (chunk) => handleChunk(task, chunk));
  child.stdin.end(policyJson); // sandbox reads policy on stdin
  child.on("close", (code) => finalizeTask(task, code));
}
```

## Architectural Boundaries
- **NO direct process spawning**: all detached execution goes through `launchSandboxProcess()`.
- **NO duplicated guard logic**: command blocking and visible-output redaction come from `lib/preflight.ts`.
- **NO persistent task store**: task state is session-local and cleaned up on `session_shutdown`.

<important if="you are adding a new background-task action">
## Adding a New Background-Task Action
1. Add or extend the shared helper in `lib/background-tasks/extension.ts`.
2. Reuse id-or-pid resolution instead of introducing a second lookup path.
3. Wire the action into `bg_task`; only mirror it in `bg_status` if compatibility requires it.
4. If it changes task state, call the same UI refresh path used by spawn/stop/finalize.
5. If it emits model-visible output, run it through the existing redaction path.
</important>

<important if="you are adding a new background-task UI affordance">
## Adding a New UI Surface
1. Decide whether it belongs in the widget, dashboard, `/bg`, a tool, or a shortcut.
2. Reuse the existing `tasks` map and lifecycle helpers; do not fork task management.
3. Keep headless callers on a text fallback instead of throwing.
4. Keep the widget lightweight and only poll while live tasks exist.
</important>
