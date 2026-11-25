// pw-blue-guard v1: PasteWarden blue-team guard for opencode 2.x
// (docs/plan/phase-5.md §5.5.1). V2 plugin API: ctx.tool.hook("execute.before");
// the V1 hook key is silently ignored by opencode 2.x.
//
// Copied into the blue worktree's .opencode/plugins/ by the orchestrator,
// together with pw-blue-policy.mjs. Every call is checked twice: first by the
// path/shell/tool policy below, then by `paste-warden hook opencode` (the
// Phase 2 malicious-command check). Any error blocks the call (fail closed).
import { Plugin } from "@opencode/plugin"
import { spawnSync } from "node:child_process"
import { appendFileSync } from "node:fs"
import { DEFAULT_MAX_TOOL_CALLS, decide } from "./pw-blue-policy.mjs"

const ROOT = process.env.PW_BLUE_ROOT ?? ""
const BIN = process.env.PW_BIN ?? ""
const DENIALS = process.env.PW_BLUE_DENIALS ?? ""
const MAX = Number.parseInt(process.env.PW_BLUE_MAX_TOOL_CALLS ?? "", 10)
const TIMEOUT_MS = 10000
const state = {
  calls: 0,
  maxCalls: Number.isFinite(MAX) && MAX > 0 ? MAX : DEFAULT_MAX_TOOL_CALLS,
}

function record(tool: string, reason: string) {
  // Tool name and reason code only: never arguments (they may hold payloads).
  if (!DENIALS) return
  try {
    appendFileSync(DENIALS, JSON.stringify({ ts: new Date().toISOString(), tool, reason }) + "\n")
  } catch {}
}

function block(tool: string, reason: string): never {
  record(tool, reason)
  throw new Error(`PasteWarden blue-team policy blocked this call (${reason}). Only rules/ and corpus/ may change.`)
}

export default Plugin.define({
  id: "pw-blue-guard",
  async setup(ctx) {
    await ctx.tool.hook("execute.before", (event) => {
      const tool = String(event.tool)
      if (!ROOT || !BIN) block(tool, "guard-misconfigured")
      let verdict
      try {
        verdict = decide(tool, event.input ?? {}, state, ROOT)
      } catch {
        block(tool, "policy-error")
      }
      if (!verdict.allow) block(tool, verdict.reason)

      let r
      try {
        r = spawnSync(BIN, ["hook", "opencode"], {
          input: JSON.stringify({ tool, args: event.input ?? {} }),
          encoding: "utf8",
          timeout: TIMEOUT_MS,
        })
      } catch {
        block(tool, "hook-spawn-failed")
      }
      let v = null
      try {
        v = JSON.parse(r.stdout)
      } catch {}
      if (r.status !== 0 || v === null || typeof v.block !== "boolean") block(tool, "hook-failed")
      if (v.block) block(tool, "malicious-content")
    })
  },
})
