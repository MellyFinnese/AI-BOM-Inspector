const OpenAI = require("openai");
const client = new OpenAI();

async function classify(input) {
  return client.chat.completions.create({
    model: "gpt-4.1-mini",
    messages: [{ role: "user", content: input }]
  });
}

module.exports = { classify };
