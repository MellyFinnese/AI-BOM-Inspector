import express from "express";
import OpenAI from "openai";

const app = express();
const client = new OpenAI();
app.post("/ask", async (req, res) => {
  const prompt = req.body.prompt;
  const result = await client.responses.create({ model: "gpt-4.1", input: prompt });
  res.json(result);
});
export default app;
