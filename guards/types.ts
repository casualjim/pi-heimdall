import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export interface HeimdallConfig {
	disabled?: string[];
	sandbox?: Partial<SandboxConfig>;
	commandPolicies?: CommandPolicy[];
}

export interface CommandPolicy {
	name: string;
	blocked: string[];
	message: string;
}

export type SandboxStdio = "piped" | "inherit" | "null";

export type SandboxNetworkPolicy = "host" | "none" | string;

export type SandboxProcPolicy = "default" | "none" | string;

export interface SandboxEnvPolicy {
	allow?: string[] | null;
	deny?: string[] | null;
}

export interface SandboxFilesystemPolicy {
	deny?: string[];
	writable?: string[];
	virtual?: Record<string, string>;
}

export interface SandboxPolicyFragment {
	network?: SandboxNetworkPolicy;
	proc?: SandboxProcPolicy;
	env?: SandboxEnvPolicy;
	filesystem?: SandboxFilesystemPolicy;
}

export interface SandboxConfig extends SandboxPolicyFragment {
	/** Pi-local toggle. Not part of the native heimdall-sandbox policy. */
	enabled?: boolean;
	/** Pi-local path to the native heimdall-sandbox binary. Not forwarded to policy. */
	binaryPath?: string;
}

export interface GeneratedSandboxPolicy extends SandboxPolicyFragment {
	cwd: string;
	command: ["bash", "-c", string];
	stdio: "piped" | "inherit";
}

export interface NormalizedSandboxConfig {
	enabled: boolean;
	binaryPath?: string;
	policy: SandboxPolicyFragment;
}

/** Guards that can be disabled via the `disabled` array in heimdall.json. */
export type OptOutGuardId =
	| "secret-guard"
	| "command-policy-guard"
	| "env-protect"
	| "kubectl-secret-guard"
	| "sops-secret-guard";

export interface GuardRegisterFn {
	(pi: ExtensionAPI, config: HeimdallConfig): void | Promise<void>;
}
