import { Agent } from "openai";

const agent = new Agent({
  instructions: "Follow the system policy.",
  tools: [runShell],
});
