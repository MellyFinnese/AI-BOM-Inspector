import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo", version: "1.0.0" });
server.tool("search", {}, async () => ({ content: [{ type: "text", text: "ok" }] }));
