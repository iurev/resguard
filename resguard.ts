/**
 * resguard extension for the pi coding agent — guards the model-driven `bash`
 * tool with the same user-wide systemd resource budget the Codex PreToolUse
 * hook uses.
 *
 * On every `bash` tool_call it sends the Codex-shaped PreToolUse payload to
 * the installed trampoline (~/.local/lib/resguard/hook.py). On "allow" the
 * command is replaced with resguard's rewrite, which runs it inside a
 * transient systemd unit with kernel-enforced limits (memory, CPU, tasks,
 * runtime, and optional disk bandwidth). On "deny", or if the guard is
 * unavailable, the tool call is blocked — fail closed, like Codex.
 *
 * The transcript keeps showing the original command; only execution changes.
 * Scope matches the Codex `^Bash$` matcher: the model's `bash` tool only.
 */
import { isToolCallEventType, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { spawn } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";

const HOOK = join(homedir(), ".local/lib/resguard/hook.py");
const PYTHON = "/usr/bin/python3";
const HOOK_TIMEOUT_MS = 10_000; // same timeout the Codex hook registration uses
const MAX_STDOUT_BYTES = 1024 * 1024;

interface GuardResponse {
	hookSpecificOutput?: {
		hookEventName?: string;
		permissionDecision?: "allow" | "deny";
		updatedInput?: { command?: string };
		permissionDecisionReason?: string;
	};
}

function runGuardHook(payload: string, signal: AbortSignal | undefined): Promise<string> {
	return new Promise((resolve, reject) => {
		let settled = false;
		let stdout = "";
		const child = spawn(PYTHON, [HOOK], { signal });
		const timer = setTimeout(() => child.kill("SIGKILL"), HOOK_TIMEOUT_MS);
		const fail = (err: Error) => {
			if (!settled) {
				settled = true;
				clearTimeout(timer);
				reject(err);
			}
		};
		child.stdout.on("data", (chunk: Buffer) => {
			stdout += chunk;
			if (stdout.length > MAX_STDOUT_BYTES) child.kill("SIGKILL");
		});
		child.stderr.on("data", () => {}); // drain; the trampoline reports via stdout
		child.stdin.on("error", () => {}); // EPIPE if the hook died early
		child.on("error", fail);
		child.on("close", (code) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			if (code === 0) resolve(stdout);
			else fail(new Error(`hook exited with code ${String(code)}`));
		});
		child.stdin.end(payload);
	});
}

export default function (pi: ExtensionAPI) {
	pi.on("tool_call", async (event, ctx) => {
		if (!isToolCallEventType("bash", event)) return;
		const { command } = event.input;
		if (typeof command !== "string" || command === "") return; // let the tool report its own error

		// Same payload shape the Codex PreToolUse hook receives.
		const payload = JSON.stringify({
			tool_name: "Bash",
			tool_input: { command },
			tool_use_id: event.toolCallId,
			session_id: ctx.sessionManager.getSessionId(),
			cwd: ctx.cwd,
		});

		let response: GuardResponse;
		try {
			response = JSON.parse(await runGuardHook(payload, ctx.signal)) as GuardResponse;
		} catch (err) {
			return {
				block: true,
				reason: `resguard unavailable; command was not executed: ${
					err instanceof Error ? err.message : String(err)
				}`,
			};
		}

		const h = response?.hookSpecificOutput;
		if (h?.permissionDecision === "allow" && typeof h.updatedInput?.command === "string" && h.updatedInput.command) {
			// In-place mutation; pi executes the rewritten command under the resguard budget.
			event.input.command = h.updatedInput.command;
			return;
		}
		return { block: true, reason: h?.permissionDecisionReason || "resguard denied the command" };
	});
}
