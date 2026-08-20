import OpenAI from "openai";

const client = new OpenAI();

export async function handler() {
  return client.responses.create({ model: "gpt-4.1", input: "safe" });
}
