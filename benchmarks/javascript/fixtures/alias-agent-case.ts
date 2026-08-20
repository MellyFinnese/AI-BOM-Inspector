import { Agent } from "openai";

const AgentCase = Agent;
const agent = new AgentCase({ instructions: trustedInstructions, tools: [runShell] });
export { agent };
