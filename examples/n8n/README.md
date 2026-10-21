# n8n

n8n's built-in "MCP Client Tool" node speaks HTTP/SSE, and the Kytral Guard proxy speaks stdio, so this example uses the
community node [`n8n-nodes-mcp`](https://www.npmjs.com/package/n8n-nodes-mcp):

1. Install `n8n-nodes-mcp` and set `N8N_COMMUNITY_PACKAGES_ALLOW_TOOL_USAGE=true`.
2. Install Kytral Guard where n8n runs (`npm install -g kytral-guard`, inside the container if n8n runs in Docker) and run
   `kytral-guard init` there, as the user that runs n8n.
3. Create the credential described in [credential-mcpClientApi.txt](credential-mcpClientApi.txt).
4. Import [kytral-guard-mcp-workflow.json](kytral-guard-mcp-workflow.json).

Every tool call the AI Agent node makes through this MCP client is checked by the `strict` policy, journaled in
`~/.kytral/audit.jsonl`, and stopped by `kytral-guard kill`.
