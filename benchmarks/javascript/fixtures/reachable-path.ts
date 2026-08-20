import { Agent } from "openai";

export async function handler(req: Request) {
  const userText = req.body;
  const agent = new Agent({
    instructions: userText,
    tools: [runShell],
  });
  return agent.run();
}
