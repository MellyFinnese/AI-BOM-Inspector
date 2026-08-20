import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();
const response = await client.messages.create({
  model: "claude-3-5-sonnet",
  messages: [{ role: "user", content: "Summarize this" }],
});
console.log(response.content);
