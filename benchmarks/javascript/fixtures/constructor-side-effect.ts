const AgentCtor = Agent;
const agent = new AgentCtor({ instructions: trustedInstructions, tools: [runShell] });
export default agent;
