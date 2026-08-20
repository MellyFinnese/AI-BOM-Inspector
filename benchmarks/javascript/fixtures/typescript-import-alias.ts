import OpenAIClient from "openai";

const api = new OpenAIClient();
export async function run(input: string) {
  return api.chat.completions.create({
    model: "gpt-4.1-mini",
    messages: [{ role: "user", content: input }],
  });
}
