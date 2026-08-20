import { generateText, streamText } from "ai";

export async function summarize(prompt: string) {
  return generateText({ model: "gpt-4.1-mini", prompt });
}

export async function stream(prompt: string) {
  return streamText({ model: "gpt-4.1-mini", prompt });
}
