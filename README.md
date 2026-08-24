# Coding Assistant Challenge: Basic Auth

This project serves as a test for LLM-based coding assistants, challenging them to add basic authentication functionality into a skeleton [Hono](https://hono.dev/)-based web app.

Run with Node.js:
```
npm install
npm start
```
and then open `localhost:3000`.

See the following table for how different LLM coding assistants performed on this task:

| Model | Harness | Duration | Cost |
|---|---|:---:|---:|
| DeepSeek V4 Flash ([branch](../../tree/opencode/deepseek-v4-flash), [commits](../../commits/opencode/deepseek-v4-flash)) | OpenCode | 29 mins | $0.04 |
| Kimi K2.6 ([branch](../../tree/opencode/kimi-2.6), [commits](../../commits/opencode/kimi-2.6)) | OpenCode | 17 mins | $1.16 |
| MiniMax M3 ([branch](../../tree/opencode/minimax-m3), [commits](../../commits/opencode/minimax-m3)) | OpenCode | 24 mins | $1.50 |
| Sonnet 4.6 ([branch](../../tree/claude-code/sonnet-4.6), [commits](../../commits/claude-code/sonnet-4.6)) | Claude Code | 13 mins | $3.39 |
| Kimi K3 ([branch](../../tree/opencode/kimi-k3), [commits](../../commits/opencode/kimi-k3)) | OpenCode | 47 mins | $3.60 |
| GLM 5.3 ([branch](../../tree/opencode/glm-5.3), [commits](../../commits/opencode/glm-5.3)) | OpenCode | 41 mins | $3.76 |
| Qwen 3.7 Max ([branch](../../tree/opencode/qwen-3.7-max), [commits](../../commits/opencode/qwen-3.7-max)) | OpenCode | 14 mins | $3.79 |
| GPT 5.5 ([branch](../../tree/codex/gpt-5.5), [commits](../../commits/codex/gpt-5.5)) | Codex | 18 mins | $4.29 |
| GLM 5.2 ([branch](../../tree/opencode/glm-5.2), [commits](../../commits/opencode/glm-5.2)) | OpenCode | 37 mins | $4.88 |
| Opus 4.8 ([branch](../../tree/claude-code/opus-4.8), [commits](../../commits/claude-code/opus-4.8)) | Claude Code | 17 mins | $7.99 |
| Opus 5 ([branch](../../tree/claude-code/opus-5), [commits](../../commits/claude-code/opus-5)) | Claude Code | 27 mins | $10.67 |
| Fable 5 ([branch](../../tree/claude-code/fable-5), [commits](../../commits/claude-code/fable-5)) | Claude Code | 19 mins | $11.44 |
| Gemini 3.5 Flash ([branch](../../tree/antigravity/gemini-3.5-flash), [commits](../../commits/antigravity/gemini-3.5-flash)) | Antigravity | 10 mins | N/A |
| Ox Alpha ([branch](../../tree/opencode/Ox-alpha), [commits](../../commits/opencode/Ox-alpha)) | OpenCode | 53 mins | N/A |

