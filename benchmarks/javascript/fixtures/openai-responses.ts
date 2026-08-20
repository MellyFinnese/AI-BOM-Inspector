import OpenAI from "openai";

const client = new OpenAI();
export async function run(prompt: string) {
  return client.responses.create({ model: "gpt-4.1", input: prompt });
}
