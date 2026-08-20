import OpenAI from "openai";

const SDK = OpenAI;
const AgentAlias = Agent;
const agent = new AgentAlias({ instructions: trustedInstructions, tools: [runShell] });

export { agent, SDK };
