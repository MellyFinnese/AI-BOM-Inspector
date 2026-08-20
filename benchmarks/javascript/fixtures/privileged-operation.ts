import { Agent } from "openai";
import { exec } from "child_process";

const agent = new Agent({ instructions: trustedInstructions, tools: [runCommand] });
exec("uname -a");

export { agent };
