# Tier 2 (scan --llm, llm check) and the MCP redteam profile. Prefix cli-.

## scan --llm / llm check

cli-llm-disabled = AI features are off (no llm.toml, or enabled = false). Showing the local analysis only.
cli-llm-config-error = The AI config cannot be used ({ $code }): { $path }. Showing the local analysis only.
cli-llm-refused-secrets = The text contains secrets, so it was not sent to a cloud model. Showing the local analysis only.
cli-llm-skipped = The local analysis found no suspicious command, so the model was not asked (only_high_risk).
cli-llm-failed = The AI explanation was discarded ({ $code }). Showing the local analysis only.
cli-llm-heading = AI explanation ({ $provider } / { $model }; the AI can only raise the risk, never lower it):
cli-llm-level = AI verdict: { $level }
cli-llm-techniques = Techniques: { $list }
cli-llm-check-ok = AI endpoint OK: { $provider } / { $model } returned valid JSON (verdict on the sample: { $level }).
cli-llm-check-failed = AI endpoint check failed: { $code }

## mcp --profile redteam

cli-mcp-bench-too-many = Too many items: at most { $max } per call.
cli-mcp-bench-id-too-long = An item id is too long: at most { $max } characters.
cli-mcp-validator-missing = The syntax validator could not be started; check --validator-cmd.
