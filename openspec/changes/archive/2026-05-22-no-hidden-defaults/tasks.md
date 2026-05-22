## 1. Config Loading and Defaults

- [x] 1.1 Add JSONC parsing support for Heimdall config files while preserving existing JSON compatibility.
- [x] 1.2 Implement config path discovery that uses generated `heimdall.default.jsonc`, prefers `heimdall.jsonc` and `.pi/heimdall.jsonc` for user/project config, and falls back to user/project `.json` files.
- [x] 1.3 Add generation/refresh of `~/.pi/agent/heimdall.default.jsonc` with comments, `sandbox.enabled: false`, `sandbox.useDefaultFilesystemDeny: true`, and the recommended private-path deny list.
- [x] 1.4 Update config assembly to merge generated defaults first, user config second, and project config last.

## 2. Sandbox Policy Behavior

- [x] 2.1 Add `sandbox.useDefaultFilesystemDeny` to TypeScript config types as a Pi-local option that is not forwarded to the native sandbox policy.
- [x] 2.2 Apply `useDefaultFilesystemDeny: false` so generated default deny entries are excluded while explicit user/project deny entries remain active.
- [x] 2.3 Remove hidden `DEFAULT_PRIVATE_PATHS` merging from sandbox normalization and native policy generation.
- [x] 2.4 Update host-tool filesystem checks to use only effective config deny entries plus explicit `.heimdall-deny` fragments.

## 3. Tests

- [x] 3.1 Add tests that JSONC config files with comments/trailing commas load correctly.
- [x] 3.2 Add tests that legacy `.json` config files still load when `.jsonc` is absent.
- [x] 3.3 Add tests that `.jsonc` is preferred over `.json` at the same user or project config level.
- [x] 3.4 Add tests for generated default config contents and generated-file overwrite behavior.
- [x] 3.5 Add tests for default/user/project precedence and `useDefaultFilesystemDeny: false` opt-out behavior.
- [x] 3.6 Update sandbox-guard tests that currently assert hardcoded default private paths are always appended.

## 4. Documentation and Verification

- [x] 4.1 Update README configuration docs to describe JSONC support, user/project `.json` compatibility, file precedence, and `.jsonc` preference.
- [x] 4.2 Update README sandbox docs to describe `heimdall.default.jsonc`, generated-file ownership, and `sandbox.useDefaultFilesystemDeny`.
- [x] 4.3 Run `npm run typecheck`.
- [x] 4.4 Run `npm test`.
- [x] 4.5 Run `npm run check:pack`.
