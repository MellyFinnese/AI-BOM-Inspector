const examples = [
  "new Agent({ tools: [runShell] })",
  "process.env.SECRET",
  "client.chat.completions.create()",
];

export function renderExamples() {
  return examples.join("\n");
}
