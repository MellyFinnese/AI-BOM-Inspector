import OpenAI from "openai";
import { generateText } from "ai";

const client = new OpenAI();
const result = await generateText({ model: "gpt-4.1", prompt: "Summarize this document" });
console.log(result.text);
