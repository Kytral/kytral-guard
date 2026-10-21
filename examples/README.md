# Examples

| Directory | What |
|---|---|
| [policies/](policies) | policy files: a team policy for coding agents, a strict policy for MCP servers |
| [claude-code/](claude-code) | the hook `kytral-guard init claude-code` installs, and an MCP server wrapped by the proxy |
| [cursor/](cursor) | the hooks `kytral-guard init cursor` installs, and a wrapped MCP server |
| [n8n/](n8n) | an n8n AI agent whose MCP tools go through the proxy |
| [sdk/](sdk) | guarding your own tools in TypeScript |
| [python/](python) | guarding the tools of a Python agent (LangChain, CrewAI, custom) with `kytral-guard hook generic` |

Prefer `kytral-guard init <agent>` to copying hook files by hand: it writes absolute paths for your machine and merges
with your existing configuration. Replace `/PATH/TO/...` placeholders in the files below.
