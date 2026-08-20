import { Client } from "@modelcontextprotocol/sdk/client/index.js";

const client = new Client({ name: "demo-client", version: "1.0.0" });
await client.callTool({ name: "run_shell", arguments: { command: userCommand } });
export { client };
