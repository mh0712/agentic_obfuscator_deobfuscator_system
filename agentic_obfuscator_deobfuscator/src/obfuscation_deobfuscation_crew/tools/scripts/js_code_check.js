const fs = require("fs");
const esprima = require("esprima");

const path = process.argv[2];

try {
  const code = fs.readFileSync(path, "utf8");
  esprima.parseScript(code); // Throws if not valid JS
  console.log("true");
} catch (e) {
  console.log("false");
}
