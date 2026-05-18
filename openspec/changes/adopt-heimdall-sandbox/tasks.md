## 1. Config and Types

- [x] 1.1 Replace POC sandbox TypeScript types with native `heimdall-sandbox` policy-fragment types plus Pi-local `enabled`.
- [x] 1.2 Remove legacy sandbox config detection/translation for `networkAccess`, `writableRoots`, `systemPaths`, `etcReal`, `etcSynthetic`, `envAllowlist`, and `extraReadPaths`.
- [x] 1.3 Remove POC `paths`/`mode`/`content` config support in favor of native `filesystem.deny`, `filesystem.writable`, and `filesystem.virtual`.
- [x] 1.4 Remove TS-owned env glob and `env.set` support from sandbox config.

## 2. Native Launch Path

- [x] 2.1 Add a helper that builds a generated `heimdall-sandbox` policy from configured sandbox fields plus runtime `cwd`, `command`, and `stdio: "piped"`.
- [x] 2.2 Ensure `sandbox.enabled: false` is used only as a Pi-side toggle and is not passed to the generated native policy.
- [x] 2.3 Locate the installed `heimdall-sandbox` binary predictably, with an explicit override if needed.
- [x] 2.4 Launch sandboxed bash commands with `heimdall-sandbox exec --policy -` and write the generated policy JSON to stdin.
- [x] 2.5 Preserve timeout, abort, stdout/stderr streaming, exit-code propagation, and process-group cleanup behavior.
- [x] 2.6 Surface native launch and policy errors clearly when sandboxing was requested.

## 3. Remove POC Runtime Logic

- [x] 3.1 Remove direct bubblewrap discovery and argument construction from `sandbox-guard.ts`.
- [x] 3.2 Remove synthetic directory/file staging from the TypeScript guard.
- [x] 3.3 Remove Linux-only sandbox support checks from the Pi extension; let the native binary own platform support.
- [x] 3.4 Decide whether host-side `read`/`write`/`edit`/`grep`/`find`/`ls` path enforcement should be removed or redesigned as a separate Pi-only requirement.

## 4. Tests and Documentation

- [x] 4.1 Replace sandbox-guard tests that assert bwrap args or POC path access with native policy generation tests.
- [x] 4.2 Add tests for disabled sandbox behavior and `--no-sandbox` behavior.
- [x] 4.3 Add tests for `heimdall-sandbox exec --policy -` spawn arguments and stdin policy writing.
- [x] 4.4 Update README sandbox configuration examples to the native policy schema.
- [x] 4.5 Document migration from the POC `paths` schema to `filesystem` patterns.
- [x] 4.6 Run `npm run typecheck`, `npm test`, and `npm run check:pack`.
