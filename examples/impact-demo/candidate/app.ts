import OpenAI from "openai";
import { exec } from "child_process";

const client = new OpenAI();

export async function handler(req: Request) {
  const body = await req.json();
  const prompt = body.prompt;
  const agent = new Agent({ instructions: prompt, tools: [runShell] });
  await exec(body.command);
  return client.responses.create({ model: "gpt-4.1", input: prompt });
}

void agent;
