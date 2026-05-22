## Context

Heimdall currently loads user config from `~/.pi/agent/heimdall.json` and project config from `<cwd>/.pi/heimdall.json`, then deep-merges project over user. The sandbox guard also owns a TypeScript `DEFAULT_PRIVATE_PATHS` list that is merged into `sandbox.filesystem.deny` and used by host-tool path checks. That means part of the effective policy is not visible in user config, even though users may need to inspect, disable, or tune it.

The desired model is transparent defaults: Heimdall can continue shipping recommended private-path denies, but those defaults should be materialized into a generated config file under the Pi agent directory and loaded like normal config. JSONC support should apply to all Heimdall config files so examples and user configs can contain explanatory comments.

## Goals / Non-Goals

**Goals:**

- Make recommended sandbox defaults visible in `~/.pi/agent/heimdall.default.jsonc`.
- Keep sandbox delegation disabled by default.
- Support `.jsonc` and `.json` config files at user and project levels; generated defaults use `.jsonc` only.
- Prefer `.jsonc` when both `.jsonc` and `.json` exist for the same user or project config level.
- Let user/project config disable generated filesystem denies with `sandbox.useDefaultFilesystemDeny: false`.
- Remove hidden private-path deny enforcement from `sandbox-guard.ts`.
- Preserve existing `heimdall.json` compatibility.

**Non-Goals:**

- Redesign native `heimdall-sandbox` policy semantics.
- Remove explicit `.heimdall-deny` or `.heimdall-write` fragment behavior.
- Add interactive config migration prompts.
- Treat the generated default file as user-owned state; it may be overwritten by Heimdall.

## Decisions

### Generate transparent defaults as JSONC

Heimdall should ensure `~/.pi/agent/heimdall.default.jsonc` exists and contains the current recommended defaults, including a comment that the file is generated, may be overwritten, and exists for transparency. The generated config should include `sandbox.enabled: false`, `sandbox.useDefaultFilesystemDeny: true`, and the recommended `sandbox.filesystem.deny` list.

Alternative considered: put defaults in `~/.pi/agent/heimdall.json`. That makes first-run behavior visible, but it either overwrites user-owned config or stops Heimdall from updating recommendations. A generated `heimdall.default.jsonc` separates updateable defaults from user-owned overrides.

### Parse Heimdall config as JSONC everywhere

Config discovery should support both `.jsonc` and `.json` names for user and project config, parsing both with a JSONC-capable parser. Generated defaults should use `.jsonc` only. New examples and generated files should use `.jsonc`, while existing user/project `.json` files continue to work.

Alternative considered: support JSONC only for the generated default file. That would make comments available in defaults but not in user/project configs, which is inconsistent and less useful.

### Prefer JSONC over JSON per config level

For each user or project level, Heimdall should prefer the `.jsonc` file and fall back to `.json` only when the `.jsonc` file is absent. The effective precedence remains generated default first, then user, then project.

This avoids ambiguous merges between two same-level user/project files and gives a simple migration path: users can create `heimdall.jsonc` and leave old `heimdall.json` in place until they remove it.

### Keep default filesystem denies explicitly disableable

`sandbox.useDefaultFilesystemDeny: false` should remove the generated default deny entries from the effective sandbox filesystem deny policy. User/project `sandbox.filesystem.deny` entries and `.heimdall-deny` fragment entries should continue to apply.

The switch is intentionally top-level under `sandbox` rather than encoded as an array replacement operation because the user intent is clearer: disable recommended defaults while keeping explicit local policy.

### Enforcement reads merged config only

`sandbox-guard.ts` should stop using a hidden `DEFAULT_PRIVATE_PATHS` list for normalization and host-tool checks. Recommended default denies enter the runtime only by being loaded from `heimdall.default.jsonc`. Explicit fragments such as `.heimdall-deny` can still extend host-tool denial behavior because those files are visible project-local policy inputs.

## Risks / Trade-offs

- Generated defaults may overwrite local edits to `heimdall.default.jsonc` → Mitigation: document the file as generated and require user changes in `heimdall.jsonc` or project config.
- Array merge semantics can make it hard to distinguish generated denies from explicit denies → Mitigation: track the generated default deny entries before merge or apply `useDefaultFilesystemDeny` during config assembly so only fallback deny entries are removed.
- Supporting both `.jsonc` and `.json` can confuse discovery → Mitigation: document `.jsonc` preference and avoid merging two user/project files at the same level.
- Removing hidden fallback denies could reduce protection if generated default creation fails → Mitigation: fail closed only for config-generation errors that prevent writing defaults, or at minimum notify clearly that recommended defaults were not loaded.

## Migration Plan

1. Add JSONC parsing and config path discovery for generated default JSONC plus user/project JSONC and JSON levels.
2. Generate or refresh `~/.pi/agent/heimdall.default.jsonc` with recommended defaults on session start.
3. Load generated defaults, user config, and project config with user/project `.jsonc` preference and `.json` compatibility.
4. Apply `sandbox.useDefaultFilesystemDeny: false` by excluding generated default deny entries from the effective policy.
5. Remove `DEFAULT_PRIVATE_PATHS` runtime enforcement from `sandbox-guard.ts`.
6. Update README and tests to cover JSONC support, precedence, generated defaults, opt-out behavior, and legacy JSON compatibility.

## Open Questions

- Should Heimdall notify when both `.jsonc` and `.json` exist at the same level and `.json` is ignored?
- Should failure to write `heimdall.default.jsonc` block sandbox activation, or should Heimdall warn and continue with user/project config only?
