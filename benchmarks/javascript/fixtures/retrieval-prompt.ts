import { Agent } from "openai";

const context = await retriever.similaritySearch("customer request");
const instructions = context.map((item) => item.pageContent).join("\n");
const agent = new Agent({ instructions });
export default agent;
