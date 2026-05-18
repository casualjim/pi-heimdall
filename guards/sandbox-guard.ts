/**
 * sandbox-guard
 *
 * Delegates sandboxed bash commands to the native heimdall-sandbox runtime.
 * The Pi extension owns only the local enabled toggle, bash wrapping, and
 * per-command policy generation.
 */

import {
	createBashTool,
	isToolCallEventType,
	type BashOperations,
	type ExtensionAPI,
} from "@earendil-works/pi-coding-agent";
import { execSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import ignore from "ignore";
import { homedir } from "node:os";
import { delimiter, join, resolve, relative } from "node:path";
import type {
	GeneratedSandboxPolicy,
	HeimdallConfig,
	NormalizedSandboxConfig,
	SandboxConfig,
	SandboxFilesystemPolicy,
	SandboxPolicyFragment,
} from "./types.js";

export const MISSING_BINARY_MESSAGE =
	"heimdall sandbox: heimdall-sandbox binary not found on PATH. " +
	"Install it with Homebrew from the casualjim tap, install @casualjim/heimdall-sandbox with npm, " +
	"or run via npx @casualjim/heimdall-sandbox. You can also set sandbox.binaryPath.";

const DEFAULT_PRIVATE_PATHS = [
	"~/Private",
	"~/.ssh",
	"~/.config",
	"~/.aws",
	"~/.azure",
	"~/.gcloud",
	"~/.oci",
	"~/.kube",
	"~/.docker",
	"~/.gnupg",
	"~/.sops",
	"~/.age",
	"~/.password-store",
	"~/.terraform.d",
	"~/.vault-token",
	"~/.netrc",
	"~/.npmrc",
	"~/.pypirc",
	"~/.cargo/credentials",
	"~/.cargo/credentials.toml",
	// AI coding tools (CLI agents, AI-native IDEs) — API keys commonly stored here.
	"~/.claude",
	"~/.codex",
	"~/.forge",
	"~/.cursor",
	"~/.windsurf",
	"~/.antigravity",
	"~/.kiro",
	"~/.augment",
	"~/.zed",
	"~/.aider",
	"~/.gemini",
	"~/.continue",
	"~/.codeium",
	"~/.openai",
	"~/.anthropic",
	// Editor / IDE configs (may contain stored auth tokens)
	"~/.vscode",
	"~/.vscode-server",
	"~/.code",
	"~/.config/JetBrains",
	"~/.local/share/JetBrains",
	"~/.config/nvim",
	"~/.local/share/nvim",
	"~/.vim",
  "~/.viminfo",
];

interface LegacyPathsConfig {
	[key: string]: { mode: string };
}

function migratePathsToFilesystem(paths: LegacyPathsConfig): SandboxFilesystemPolicy {
	const deny: string[] = [];
	const writable: string[] = [];
	for (const [path, entry] of Object.entries(paths)) {
		if (entry.mode === "deny") deny.push(path);
		else if (entry.mode === "write" || entry.mode === "writable") writable.push(path);
	}
	const fs: SandboxFilesystemPolicy = {};
	if (deny.length > 0) fs.deny = deny;
	if (writable.length > 0) fs.writable = writable;
	return fs;
}

export function normalizeSandboxConfig(
	config?: SandboxConfig | Record<string, unknown>,
	configPath?: string,
): NormalizedSandboxConfig {
	const raw = config ?? {};
	const sandbox = { ...raw } as SandboxConfig & { paths?: LegacyPathsConfig };
	const policy: SandboxPolicyFragment = {};

	if (sandbox.paths && typeof sandbox.paths === "object" && !sandbox.filesystem) {
		sandbox.filesystem = migratePathsToFilesystem(sandbox.paths);
		delete sandbox.paths;

		if (configPath) {
			try {
				const full = JSON.parse(readFileSync(configPath, "utf-8"));
				if (full.sandbox?.paths && !full.sandbox?.filesystem) {
					full.sandbox.filesystem = sandbox.filesystem;
					delete full.sandbox.paths;
					writeFileSync(configPath, JSON.stringify(full, null, 2) + "\n");
				}
			} catch {
				// best-effort migration
			}
		}
	}

	if (sandbox.network !== undefined) policy.network = sandbox.network;
	if (sandbox.proc !== undefined) policy.proc = sandbox.proc;
	if (sandbox.env !== undefined) {
		policy.env = {};
		if (sandbox.env.allow !== undefined) policy.env.allow = sandbox.env.allow;
		if (sandbox.env.deny !== undefined) policy.env.deny = sandbox.env.deny;
	}
	if (sandbox.filesystem !== undefined) {
		policy.filesystem = { ...sandbox.filesystem };
	} else {
		policy.filesystem = {};
	}

	// Merge DEFAULT_PRIVATE_PATHS into deny so the sandbox binary enforces them too
	const configDeny = policy.filesystem.deny ?? [];
	const defaultsToAdd = DEFAULT_PRIVATE_PATHS.filter((p) => !configDeny.includes(p));
	if (defaultsToAdd.length > 0) {
		policy.filesystem.deny = [...configDeny, ...defaultsToAdd];
	}

	return {
		enabled: sandbox.enabled ?? false,
		...(sandbox.binaryPath ? { binaryPath: sandbox.binaryPath } : {}),
		policy,
	};
}

export function buildSandboxPolicy(
	config: NormalizedSandboxConfig,
	cwd: string,
	command: string,
	stdio: "inherit" | "piped" = "piped",
): GeneratedSandboxPolicy {
	return {
		...config.policy,
		cwd,
		command: ["bash", "-c", command],
		stdio,
	};
}


export interface SandboxBinaryResolution {
	binaryPath: string;
	found: boolean;
	source: "config" | "npm" | "path" | "default";
}

export function resolveHeimdallSandboxBinary(configuredBinaryPath?: string): SandboxBinaryResolution {
	if (configuredBinaryPath?.trim()) {
		return { binaryPath: configuredBinaryPath.trim(), found: true, source: "config" };
	}

	// Try npm-installed platform binary first
	for (const pkg of [
		"@casualjim/heimdall-sandbox-darwin-arm64",
		"@casualjim/heimdall-sandbox-linux-x64",
		"@casualjim/heimdall-sandbox-linux-arm64",
	]) {
		try {
			const candidate = require.resolve(`${pkg}/bin/heimdall-sandbox`);
			if (existsSync(candidate)) return { binaryPath: candidate, found: true, source: "npm" };
		} catch {
			// Package not installed on this platform
		}
	}

	// Try PATH lookup
	const binaryName = "heimdall-sandbox";
	const pathEnv = process.env.PATH ?? "";
	for (const dir of pathEnv.split(delimiter)) {
		if (!dir) continue;
		const candidate = join(dir, binaryName);
		if (existsSync(candidate)) return { binaryPath: candidate, found: true, source: "path" };
	}

	return { binaryPath: binaryName, found: false, source: "default" };
}

export function findHeimdallSandboxBinary(): string {
	return resolveHeimdallSandboxBinary().binaryPath;
}

type SpawnLike = typeof spawn;

function killProcessGroup(child: ChildProcessWithoutNullStreams): void {
	if (!child.pid) {
		child.kill("SIGKILL");
		return;
	}

	try {
		process.kill(-child.pid, "SIGKILL");
	} catch {
		child.kill("SIGKILL");
	}
}

export function createSandboxedBashOps(
	config: NormalizedSandboxConfig,
	defaultCwd: string,
	options: { binaryPath?: string; spawnFn?: SpawnLike } = {},
): BashOperations {
	const binaryPath = options.binaryPath ?? findHeimdallSandboxBinary();
	const spawnFn = options.spawnFn ?? spawn;

	return {
		async exec(command, execCwd, { onData, signal, timeout, env }) {
			const workDir = execCwd || defaultCwd;
			if (!existsSync(workDir)) {
				throw new Error(`Working directory does not exist: ${workDir}`);
			}

			const policy = buildSandboxPolicy(config, workDir, command);
			const policyJson = `${JSON.stringify(policy)}\n`;

			return await new Promise((resolve, reject) => {
				let settled = false;
				const settleReject = (error: Error) => {
					if (settled) return;
					settled = true;
					reject(error);
				};
				const settleResolve = (exitCode: number | null) => {
					if (settled) return;
					settled = true;
					resolve({ exitCode });
				};

				const child = spawnFn(binaryPath, ["exec", "--policy", "-"], {
					cwd: workDir,
					env: env ?? process.env,
					detached: true,
					stdio: ["pipe", "pipe", "pipe"],
				});

				let timedOut = false;
				let timeoutHandle: NodeJS.Timeout | undefined;

				if (timeout !== undefined && timeout > 0) {
					timeoutHandle = setTimeout(() => {
						timedOut = true;
						killProcessGroup(child);
					}, timeout * 1000);
				}

				child.stdout.on("data", onData);
				child.stderr.on("data", onData);

				child.on("error", (err) => {
					if (timeoutHandle) clearTimeout(timeoutHandle);
					settleReject(new Error(
						`Failed to launch heimdall-sandbox at ${JSON.stringify(binaryPath)}: ${err.message}`,
					));
				});

				const onAbort = () => {
					killProcessGroup(child);
				};

				signal?.addEventListener("abort", onAbort, { once: true });

				child.on("close", (code) => {
					if (timeoutHandle) clearTimeout(timeoutHandle);
					signal?.removeEventListener("abort", onAbort);

					if (signal?.aborted) {
						settleReject(new Error("aborted"));
					} else if (timedOut) {
						settleReject(new Error(`timeout:${timeout}`));
					} else {
						settleResolve(code);
					}
				});

				child.stdin.end(policyJson);
			});
		},
	};
}

export function registerSandboxGuard(pi: ExtensionAPI, getHeimdallConfig: () => HeimdallConfig, getConfigPath?: () => string | undefined): void {
	let sandboxConfig: NormalizedSandboxConfig | null = null;
	let sandboxCwd = process.cwd();
	let sandboxBinary = resolveHeimdallSandboxBinary().binaryPath;

	pi.registerFlag("no-sandbox", {
		description: "Disable native heimdall-sandbox delegation for bash commands",
		type: "boolean",
		default: false,
	});

	pi.on("session_start", async (_event, ctx) => {
		sandboxCwd = ctx.cwd;
		const noSandbox = pi.getFlag("no-sandbox") as boolean;
		if (noSandbox) {
			sandboxConfig = null;
			ctx.ui.notify("heimdall sandbox: disabled via --no-sandbox", "warning");
			return;
		}

		const config = normalizeSandboxConfig(
			getHeimdallConfig().sandbox as SandboxConfig | undefined,
			getConfigPath?.(),
		);
		const binaryResolution = resolveHeimdallSandboxBinary(config.binaryPath);
		sandboxBinary = binaryResolution.binaryPath;
		sandboxConfig = null;
		if (!config.enabled) {
			return;
		}

		if (!binaryResolution.found) {
			ctx.ui.notify(MISSING_BINARY_MESSAGE, "warning");
		}

		sandboxConfig = config;

		const writeCount = config.policy.filesystem?.writable?.length ?? 0;
		const envDenyCount = config.policy.env?.deny?.length ?? 0;
		const envIcon = envDenyCount > 0 ? `🔒${envDenyCount}` : "";
		const networkIcon = config.policy.network === "host" ? "↔" : "⊘";
		const theme = ctx.ui.theme;

		const statusText = [
			"🛡",
			`✎${writeCount}`,
			envIcon,
			networkIcon,
		].filter(Boolean).join(" │ ");

		ctx.ui.setWidget("heimdall-sandbox", [statusText], { placement: "belowEditor" });

		ctx.ui.setStatus(
			"heimdall-sandbox",
			[
				theme.fg("accent", "🛡"),
				theme.fg("success", `✎${writeCount}`),
				theme.fg("muted", envIcon),
				theme.fg(config.policy.network === "host" ? "success" : "warning", networkIcon),
			].join(theme.fg("dim", "│")),
		);
		ctx.ui.notify("heimdall sandbox: active", "info");
	});

	const defaultOps = () => createSandboxedBashOps(sandboxConfig!, sandboxCwd, { binaryPath: sandboxBinary });

	const localCwd = process.cwd();
	const localBash = createBashTool(localCwd);

	pi.registerTool({
		...localBash,
		label: "bash (heimdall sandbox)",
		async execute(id, params, signal, onUpdate) {
			if (!sandboxConfig) {
				return localBash.execute(id, params, signal, onUpdate);
			}

			const ops = defaultOps();
			const sandboxedBash = createBashTool(sandboxCwd, { operations: ops });
			return sandboxedBash.execute(id, params, signal, onUpdate);
		},
	});

	pi.on("user_bash", async (_event) => {
		if (!sandboxConfig) return undefined;

		return {
			operations: defaultOps(),
		};
	});

	function untildify(path: string): string {
		return path.replace(/^~(?=\/|$)/, homedir());
	}

	function loadFragmentFile(cwd: string, filename: string): string[] {
		const filepath = join(cwd, filename);
		if (!existsSync(filepath)) return [];
		try {
			return readFileSync(filepath, "utf-8")
				.split(/\r?\n/)
				.map((line) => line.trim())
				.filter((line) => line.length > 0 && !line.startsWith("#"));
		} catch {
			return [];
		}
	}

	function isDenied(filesystem: SandboxFilesystemPolicy | undefined, cwd: string, rawPath: string): boolean {
		const denyPatterns = [...DEFAULT_PRIVATE_PATHS, ...(filesystem?.deny ?? []), ...loadFragmentFile(cwd, ".heimdall-deny")];
		const expandedPatterns = denyPatterns.map((p) => resolve(cwd, untildify(p)));
		const target = resolve(cwd, untildify(rawPath));

		// Absolute path patterns: prefix match
		for (const abs of expandedPatterns) {
			if (target === abs || target.startsWith(`${abs}/`)) {
				return true;
			}
		}

		// Gitignore-style patterns: use ignore library with relative paths
		const globPatterns = denyPatterns.filter((p) => !p.startsWith("/") && !p.startsWith("~"));
		if (globPatterns.length > 0) {
			const ig = ignore().add(globPatterns);
			const rel = relative(cwd, target);
			if (rel && !rel.startsWith("..")) {
				return ig.ignores(rel);
			}
		}

		return false;
	}

	function isWritable(filesystem: SandboxFilesystemPolicy | undefined, cwd: string, rawPath: string): boolean {
		const writePatterns = [...(filesystem?.writable ?? []), ...loadFragmentFile(cwd, ".heimdall-write")];
		if (writePatterns.length === 0) return false; // No writable policy = read-only

		const target = resolve(cwd, untildify(rawPath));

		// Resolve relative patterns to absolute for prefix matching
		const absolutePatterns = writePatterns.map((p) => resolve(cwd, untildify(p)));
		for (const abs of absolutePatterns) {
			if (target === abs || target.startsWith(`${abs}/`)) {
				return true;
			}
		}

		// Gitignore-style patterns
		const globPatterns = writePatterns.filter((p) => !p.startsWith("/") && !p.startsWith("~"));
		if (globPatterns.length > 0) {
			const ig = ignore().add(globPatterns);
			const rel = relative(cwd, target);
			if (rel && !rel.startsWith("..")) {
				return ig.ignores(rel);
			}
		}

		return false;
	}

	pi.on("tool_call", async (event, ctx) => {
		if (!sandboxConfig) return undefined;

		const filesystem = sandboxConfig.policy.filesystem;

		const block = (operation: "read" | "write", path: string) => {
			const reason =
				`Blocked: ${event.toolName} attempted to ${operation} "${path}" denied by heimdall sandbox filesystem policy. ` +
				`Adjust .pi/heimdall.json to allow this path.`;
			if (ctx.hasUI) ctx.ui.notify(`heimdall sandbox: blocked ${event.toolName} ${path}`, "warning");
			return { block: true as const, reason };
		};

		const input = event.input as Record<string, unknown>;
		const path = typeof input.path === "string" ? input.path : ".";

		// Deny always blocks both read and write for host tools
		if (isDenied(filesystem, sandboxCwd, path)) {
			return block("read", path);
		}

		// Write/edit require explicit writable grant
		if (isToolCallEventType("write", event) || isToolCallEventType("edit", event)) {
			if (!isWritable(filesystem, sandboxCwd, path)) {
				return block("write", path);
			}
		}

		return undefined;
	});

	pi.registerCommand("sandbox", {
		description: "Show heimdall sandbox configuration",
		handler: async (_args, ctx) => {
			if (!sandboxConfig) {
				ctx.ui.notify("heimdall sandbox: disabled", "info");
				return;
			}

			let version = "unknown";
			try {
				version = execSync(`"${sandboxBinary}" --version`, { encoding: "utf-8" }).trim();
			} catch { /* ignore */ }

			const lines = [
				"heimdall sandbox configuration:",
				"",
				`Binary: ${sandboxBinary}`,
				`Version: ${version}`,
				"Policy fragment:",
				JSON.stringify(sandboxConfig.policy, null, 2),
			];
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});
}
