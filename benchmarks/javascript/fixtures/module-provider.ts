import { generateText as runText } from "ai";

export async function execute(prompt: string) {
  return runText({ model: "gpt-4.1-mini", prompt });
}
