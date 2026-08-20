import { Agent } from "openai";
import yargs from "yargs";

const args = yargs(process.argv.slice(2)).argv;
const agent = new Agent({ instructions: String(args.prompt) });
export default agent;
