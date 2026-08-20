import { Agent } from "openai";

const template = `User request: ${userText}`;
const agent = new Agent({ instructions: template });
export { agent };
