## 1. Port oh-pi Behavior

- [ ] 1.1 Copy the behavioral shape of `oh-pi`'s `bg-process.ts`: 10 second default threshold, explicit timeout override, PID/log response, completion follow-up, and `bg_status` actions.
- [ ] 1.2 Add an in-memory `Map<number, BgProcess>` to Heimdall's sandbox guard runtime for backgrounded commands.
- [ ] 1.3 Preserve normal foreground output behavior for commands that finish before the effective threshold.

## 2. Sandbox Launch Integration

- [ ] 2.1 Ensure backgrounded commands use the same Heimdall launch helper as foreground `bash` commands, choosing sandboxed execution when active and local shell fallback otherwise.
- [ ] 2.2 Keep any sandbox resources needed by each background command alive until the process exits or is stopped.
- [ ] 2.3 Ensure stop and shutdown cleanup terminate the launched process, preferring process-group kill where available.

## 3. bg_status Tool

- [ ] 3.1 Register a Heimdall-owned `bg_status` tool with `list`, `log`, and `stop` actions compatible with `oh-pi`.
- [ ] 3.2 Implement `list` output with PID, running/stopped status, exit code, log path, and command.
- [ ] 3.3 Implement `log` output using `oh-pi`-style tail/truncation behavior.
- [ ] 3.4 Implement `stop` output for tracked running, tracked finished, and missing process cases.

## 4. Tests and Documentation

- [ ] 4.1 Add tests for foreground completion, timeout-to-background response, completion follow-up state, `bg_status` actions, and shutdown cleanup.
- [ ] 4.2 Add tests or focused coverage for sandboxed background launch behavior and resource lifetime.
- [ ] 4.3 Update `README.md` to say Heimdall replaces `oh-pi`'s `bg-process.ts` and users should disable that single conflicting plugin.
- [ ] 4.4 Run `npm run typecheck`, `npm test`, and `npm run check:pack`.
