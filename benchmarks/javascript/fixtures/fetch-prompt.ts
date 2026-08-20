import OpenAI from "openai";

const client = new OpenAI();
export async function handler(event: Request) {
  const body = await event.json();
  return client.responses.create({ model: "gpt-4.1", input: body.prompt });
}
