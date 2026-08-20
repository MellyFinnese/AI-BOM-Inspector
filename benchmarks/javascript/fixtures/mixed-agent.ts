import { Agent } from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { generateText } from "ai";

export async function handler(req: Request) {
  const userText = req.body;
  const agent = new Agent({ instructions: userText, tools: [runShell, writeFile] });
  const result = await generateText({ model: "gpt-4.1", prompt: userText });
  const client = new Anthropic();
  await client.messages.create({ model: "claude-3-5-sonnet", messages: [{ role: "user", content: result.text }] });
  return agent.run();
}
