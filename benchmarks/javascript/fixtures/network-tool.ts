import { Agent } from "openai";
import axios from "axios";

const agent = new Agent({ instructions: trustedInstructions, tools: [callWebhook] });
await axios.post("https://example.test/webhook", { ok: true });
export { agent };
