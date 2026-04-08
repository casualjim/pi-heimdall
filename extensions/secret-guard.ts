/**
 * secret-guard
 *
 * Project-scoped secret protection driven by a `.env.json` file at the project
 * root. The file is a flat object whose keys name environment variables that
 * are considered secret, e.g.:
 *
 *   {
 *     "GITHUB_TOKEN": "",
 *     "OPENAI_API_KEY": "",
 *     "STRIPE_SECRET_KEY": ""
 *   }
 *
 * For each key listed, the current process env var (if set) is captured as the
 * "secret value". Values in the JSON itself are ignored — only the keys matter.
 *
 * Behavior:
 *
 *   1. `tool_call` (bash): if the command references any secret key name as a
 *      whole word, the command is blocked before it runs. This catches
 *      `echo $GITHUB_TOKEN`, `env | grep OPENAI`, etc.
 *
 *   2. `tool_result` (bash): the textual output of bash is scanned and any
 *      occurrence of a captured secret value is redacted. Redaction covers:
 *        - plaintext `KEY=value`
 *        - base64 of `KEY=value` (with and without trailing newline)
 *        - rot13 of `KEY=value`
 *        - reversed `KEY=value`
 *        - raw hex of `KEY=value` (xxd -p, od -x)
 *        - hexdump-style output from `hexdump -C`, `xxd`, and `od -c`
 *      Additionally, a generic pattern redacts values after any variable
 *      whose name ends in SECRET/KEY/TOKEN/PASSWORD/PASS/APIKEY/CREDENTIAL/PRIVATE.
 *
 * The `.env.json` file itself is loaded on `session_start` (and every
 * subsequent reload) from `ctx.cwd`. If the file does not exist or cannot be
 * parsed, the guard stays active but with an empty key set — the generic
 * trailing-pattern redaction still applies to bash output.
 *
 * Ported from opencode plugin `secret-guard.ts`.
 */

import {
	isToolCallEventType,
	isBashToolResult,
	type ExtensionAPI,
} from "@mariozechner/pi-coding-agent";
import type { ImageContent, TextContent } from "@mariozechner/pi-ai";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

type SecretValues = Record<string, string>;

const REDACTED = "[REDACTED]";

function escapeRegex(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function rot13(input: string): string {
	return input.replace(/[a-zA-Z]/g, (c) => {
		const base = c <= "Z" ? 65 : 97;
		return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
	});
}

/**
 * Extract decoded text from hexdump-style output.
 * Handles three common formats: `hexdump -C`, `xxd`, and `od -c`.
 */
function extractDecodedText(output: string): string | null {
	const lines = output.split("\n");
	const decoded: string[] = [];
	let hasHexFormat = false;

	for (const line of lines) {
		// `hexdump -C`: trailing |text|
		const pipeMatch = line.match(/\|([^|]+)\|/);
		if (pipeMatch) {
			hasHexFormat = true;
			decoded.push(pipeMatch[1] ?? "");
			continue;
		}

		// `xxd`: "address: hex hex  text" or "hex hex  text"
		const xxdMatch = line.match(
			/^(?:[0-9a-f]+:\s+)?(?:[0-9a-f]{2,4}(?:\s+[0-9a-f]{2,4})*)\s{2,}(\S.*)$/i,
		);
		if (xxdMatch) {
			hasHexFormat = true;
			decoded.push(xxdMatch[1] ?? "");
			continue;
		}

		// `od -c`: address + spaced chars
		if (/^\d+\s+/.test(line) && !line.includes("|")) {
			const parts = line.split(/^\d+\s+/);
			if (parts.length > 1 && parts[1] && /\S\s+\S/.test(parts[1])) {
				hasHexFormat = true;
				decoded.push(parts[1].replace(/\s+/g, ""));
			}
		}
	}

	return hasHexFormat ? decoded.join("") : null;
}

/** Check if raw hex output (e.g. `xxd -p`, `od -x`) contains any secret. */
function containsSecretInHex(output: string, secretValues: SecretValues): boolean {
	const lower = output.toLowerCase();
	const stripped = lower.replace(/[^0-9a-f]/g, "");

	for (const [key, value] of Object.entries(secretValues)) {
		const fullValue = `${key}=${value}`;
		const hex = Buffer.from(fullValue).toString("hex");

		if (lower.includes(hex)) return true;
		if (stripped.includes(hex)) return true;
	}
	return false;
}

function redactOutput(output: string, secretValues: SecretValues): string {
	// Short-circuit: if any hexdump-style line contains a captured value, nuke
	// the whole output. Partial redaction of a hex dump is dangerous because
	// the bytes surrounding the hit are often still enough to reconstruct it.
	const decoded = extractDecodedText(output);
	if (decoded) {
		for (const [key, value] of Object.entries(secretValues)) {
			if (!value) continue;
			if (!decoded.includes(`${key}=`)) continue;
			const tail = value.substring(0, Math.max(5, value.length - 2));
			if (decoded.includes(value) || decoded.includes(tail)) {
				return REDACTED;
			}
		}
	}

	// Same treatment for raw hex output.
	if (containsSecretInHex(output, secretValues)) {
		return REDACTED;
	}

	let result = output;

	for (const [key, value] of Object.entries(secretValues)) {
		if (!value) continue;
		const fullValue = `${key}=${value}`;

		// Plaintext.
		result = result.split(fullValue).join(REDACTED);

		// Base64 with and without a trailing newline.
		result = result
			.split(Buffer.from(fullValue).toString("base64"))
			.join(REDACTED);
		result = result
			.split(Buffer.from(`${fullValue}\n`).toString("base64"))
			.join(REDACTED);

		// Rot13.
		result = result.split(rot13(fullValue)).join(REDACTED);

		// Reversed.
		result = result.split(fullValue.split("").reverse().join("")).join(REDACTED);
	}

	// Generic pattern-based redaction for common secret variable names.
	result = result.replace(
		/(\b\w*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|APIKEY|CREDENTIAL|PRIVATE)=)\S*/gi,
		`$1${REDACTED}`,
	);

	return result;
}

export default function (pi: ExtensionAPI) {
	let secretKeys: string[] = [];
	let secretValues: SecretValues = {};
	let keyPattern: RegExp | null = null;

	async function loadEnvJson(cwd: string): Promise<void> {
		secretKeys = [];
		secretValues = {};
		keyPattern = null;

		const envPath = join(cwd, ".env.json");
		let parsed: Record<string, unknown>;
		try {
			const raw = await readFile(envPath, "utf8");
			parsed = JSON.parse(raw) as Record<string, unknown>;
		} catch {
			return;
		}

		if (!parsed || typeof parsed !== "object") return;

		secretKeys = Object.keys(parsed).filter((k) => k !== "sops");
		for (const key of secretKeys) {
			const val = process.env[key];
			if (typeof val === "string" && val.length > 0) {
				secretValues[key] = val;
			}
		}

		if (secretKeys.length > 0) {
			const escaped = secretKeys.map(escapeRegex);
			keyPattern = new RegExp(`\\b(?:${escaped.join("|")})\\b`, "i");
		}
	}

	pi.on("session_start", async (_event, ctx) => {
		await loadEnvJson(ctx.cwd);
	});

	pi.on("tool_call", async (event, ctx) => {
		if (!isToolCallEventType("bash", event)) return undefined;
		if (!keyPattern) return undefined;

		const command = event.input.command;
		if (typeof command !== "string") return undefined;

		const match = command.match(keyPattern);
		if (!match) return undefined;

		if (ctx.hasUI) {
			ctx.ui.notify(`heimdall: blocked bash referencing secret "${match[0]}"`, "warning");
		}

		return {
			block: true,
			reason:
				`Blocked: command references secret "${match[0]}". ` +
				`This is protected by pi-heimdall/secret-guard based on .env.json. ` +
				`Ask the user to run this command directly in their terminal if needed. ` +
				`Never attempt to bypass this protection or ask the user to disable it.`,
		};
	});

	pi.on("tool_result", async (event, _ctx) => {
		if (!isBashToolResult(event)) return undefined;

		// Nothing to redact against. Still apply generic pattern redaction
		// so that accidental `FOO_TOKEN=abc` in output gets masked.
		const hasValues = Object.keys(secretValues).length > 0;

		let changed = false;
		const newContent: (TextContent | ImageContent)[] = event.content.map((part) => {
			if (part.type !== "text") return part;
			if (typeof part.text !== "string") return part;

			const next = redactOutput(part.text, hasValues ? secretValues : {});
			if (next === part.text) return part;

			changed = true;
			return { ...part, text: next };
		});

		if (!changed) return undefined;
		return { content: newContent };
	});
}
