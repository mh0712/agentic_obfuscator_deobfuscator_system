const esprima = require("esprima");
const escodegen = require("escodegen");
const gnirts = require("./gnirts"); // Your custom obfuscation logic

// Convert obfuscated string code into AST node
function codeStringToASTNode(codeStr) {
  const wrapped = `(${codeStr})`; // Wrap in parentheses to parse expressions
  const parsed = esprima.parseScript(wrapped).body[0].expression;
  return parsed;
}

// Recursively walk and replace string literals with obfuscated equivalents
function obfuscateAST(node) {
  if (node.type === "Literal" && typeof node.value === "string") {
    const obfuscatedCode = gnirts.getCode(node.value); // Obfuscate string
    const newNode = codeStringToASTNode(obfuscatedCode); // Convert obfuscated code to AST
    Object.assign(node, newNode); // Replace original node
  }

  for (const key in node) {
    if (node[key] && typeof node[key] === "object") {
      if (Array.isArray(node[key])) {
        node[key].forEach((child) => obfuscateAST(child));
      } else {
        obfuscateAST(node[key]);
      }
    }
  }
}

// Main obfuscation logic
function obfuscateCode(jsCode) {
  const ast = esprima.parseScript(jsCode);
  obfuscateAST(ast);
  return escodegen.generate(ast);
}

// === Read code from stdin and output obfuscated version ===
let code = "";
process.stdin.setEncoding("utf8");

process.stdin.on("data", (chunk) => {
  code += chunk;
});

process.stdin.on("end", () => {
  try {
    const result = obfuscateCode(code);
    console.log(result); // Output obfuscated code to stdout
  } catch (err) {
    console.error("[!] Obfuscation failed:", err.message);
    process.exit(1); // Signal error to subprocess
  }
});
