import { Agent } from "openai";
import { writeFile } from "fs";

const agent = new Agent({ instructions: trustedInstructions, tools: [writeFile] });
writeFile("/tmp/output.txt", "generated");
export { agent };
