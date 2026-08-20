import { Agent } from "openai";

const policyText = process.env.SYSTEM_POLICY || "default";
const agent = new Agent({ instructions: policyText });
export default agent;
