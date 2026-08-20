export async function handler(req: Request) {
  const userText = req.body;
  return runAgent({
    instructions: userText,
    tools: [runShell],
  });
}
