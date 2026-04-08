/**
 * env-protect
 *
 * Blocks `read` tool calls that target `.env` files.
 *
 * Allows the following variants through as example/template files:
 *   .env.example, .env.sample, .env.template, .env.dist, .env.defaults
 *
 * Everything else that looks like a dotenv file (`.env`, `.env.local`,
 * `.env.production`, `.envrc`, `service.env`, etc.) is blocked.
 *
 * Ported from opencode plugin `envprotect.ts`.
 */

import { isToolCallEventType, type ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { basename } from "node:path";

const EXAMPLE_SUFFIXES = ["example", "sample", "template", "dist", "defaults"];

function isExampleVariant(name: string): boolean {
	// `.env.example`, `.env.local.example`, etc.
	const lower = name.toLowerCase();
	return EXAMPLE_SUFFIXES.some(
		(suffix) => lower.endsWith(`.${suffix}`) || lower.includes(`.${suffix}.`),
	);
}

function isDotenvPath(rawPath: string): boolean {
	// Strip any leading @ that some models like to attach to paths.
	const path = rawPath.replace(/^@/, "");
	const name = basename(path).toLowerCase();

	if (name === ".env" || name === ".envrc") return true;
	if (name.startsWith(".env.")) return !isExampleVariant(name);
	// Catch `foo.env`, `service.env` etc. but not `.env.example.txt`.
	if (name.endsWith(".env")) return !isExampleVariant(name);

	return false;
}

export default function (pi: ExtensionAPI) {
	pi.on("tool_call", async (event, ctx) => {
		if (!isToolCallEventType("read", event)) return undefined;

		const path = event.input.path;
		if (typeof path !== "string" || !isDotenvPath(path)) return undefined;

		const reason =
			`Blocked: reading dotenv file "${path}" is forbidden. ` +
			`This is protected by pi-heimdall/env-protect. ` +
			`If the user needs the contents, ask them to paste the relevant values directly. ` +
			`Never attempt to bypass this protection (cat, head, tail, xxd, base64, etc.) ` +
			`and never ask the user to disable it.`;

		if (ctx.hasUI) {
			ctx.ui.notify(`heimdall: blocked read of ${path}`, "warning");
		}

		return { block: true, reason };
	});
}
