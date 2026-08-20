import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();
export async function ask(prompt: string) {
  return client.messages.create({
    model: "claude-3-5-sonnet",
    max_tokens: 100,
    messages: [{ role: "user", content: prompt }],
  });
}
