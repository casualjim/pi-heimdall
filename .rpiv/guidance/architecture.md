# Project Overview
`pi-heimdall` is a TypeScript ESM Pi package that adds safety guards around tool execution and secret handling. It ships a default core extension plus an optional sandboxed background-task extension.

# Architecture
```text
pi-heimdall/
├── extensions/         # Pi entrypoints and composition roots
├── lib/                # all non-entrypoint implementation code
│   ├── guards/         # Pi hook adapters for blocking/redaction concerns
│   ├── sandbox/        # sandbox config, runtime launch, and filesystem policy helpers
│   └── background-tasks/ # optional detached-task feature built on sandbox/preflight helpers
└── tests/              # behavior tests, especially config semantics
```

```text
Pi loader/settings
  -> extensions/
     -> lib/                (load generated/user/project config + shared session helpers)
        -> guards/          (core guard registration and Pi event wiring)
        -> sandbox/         (native sandbox policy normalization + launch/runtime)
        -> background-tasks/ (optional feature; reuses lib + sandbox + guard detection)
```

Architecture pattern: single-package modular plugin/extension architecture. `extensions/` is the Pi-facing adapter layer; everything else is library implementation under `lib/`.

# Commands
| Command | Purpose |
|---|---|
| `npm run typecheck` | Type-check the package |
| `npm run test` | Run Vitest |
| `npm run check:pack` | Verify published package contents |
| `npm install` | Optional local tooling install |

# Business Context
This package exists to stop accidental secret exposure and unsafe command execution in Pi sessions. The optional background-task feature is a safety-focused replacement for upstream background-task tooling when sandboxed detached execution is required.

<important if="you are adding a new core guard end-to-end">
1. Add the guard module and workflow details in `.rpiv/guidance/guards/architecture.md`.
2. Register it from the composition root in `.rpiv/guidance/extensions/architecture.md`.
3. If it adds config, route it through `.rpiv/guidance/lib/architecture.md`.
4. If detached background tasks must honor it too, update the preflight reuse path in `.rpiv/guidance/background-tasks/architecture.md`.
</important>

<important if="you are enabling or extending the optional background-task feature">
1. Treat `bg_task` as the canonical API; `bg_status` is compatibility-only.
2. Keep the thin resource wrapper pattern in `.rpiv/guidance/extensions/architecture.md`.
3. Reuse the preflight and sandbox boundaries documented in `.rpiv/guidance/background-tasks/architecture.md` and `.rpiv/guidance/guards/architecture.md`.
4. Keep package docs aligned so users know the feature is opt-in and conflicts with upstream background-task packages.
</important>

<important if="you are writing or modifying tests">
- Prefer behavior-level Vitest coverage over mocking internals.
- Config semantics live mainly in `tests/heimdall-config.test.ts`; extend those tests when changing merge/default behavior.
- Add focused guard tests under `tests/*.test.ts` when changing block or redaction rules.
</important>
