const esprima = require("esprima");
const fs = require("fs");

function isJavaScriptCode(codeStr) {
  try {
    esprima.parseScript(codeStr); // Attempt to parse the code
    return true;
  } catch {
    return false;
  }
}

function entropy(str) {
  const map = {};
  for (let char of str) map[char] = (map[char] || 0) + 1;
  let total = str.length;
  return Object.values(map)
    .map((count) => (count / total) * Math.log2(total / count))
    .reduce((a, b) => a + b, 0);
}

function scoreObfuscation(code) {
  try {
    const tree = esprima.parseScript(code, { tolerant: true });

    let shortVars = 0,
      totalIdentifiers = 0,
      underscoreIdentifiers = 0,
      evalCalls = 0,
      deadCodeBlocks = 0,
      suspiciousSwitches = 0,
      suspiciousUnaryOps = 0,
      hexLiterals = 0,
      rotatingArrayDecoder = false;

    function traverse(node) {
      for (let key in node) {
        const child = node[key];
        if (typeof child === "object" && child !== null) {
          if (child.type === "Identifier") {
            totalIdentifiers++;
            if (child.name.length <= 2 && !["if", "do"].includes(child.name)) {
              shortVars++;
            }
            if (child.name.startsWith("_")) {
              underscoreIdentifiers++;
            }
          }

          if (
            child.type === "CallExpression" &&
            child.callee?.name === "eval"
          ) {
            evalCalls++;
          }

          if (
            child.type === "IfStatement" &&
            child.test?.type === "Literal" &&
            child.test.value === false
          ) {
            deadCodeBlocks++;
          }

          if (
            child.type === "SwitchStatement" &&
            child.discriminant.type === "Literal" &&
            child.cases.length > 5
          ) {
            suspiciousSwitches++;
          }

          if (
            child.type === "UnaryExpression" &&
            child.operator === "!" &&
            child.argument.type === "ArrayExpression"
          ) {
            suspiciousUnaryOps++;
          }

          traverse(child);
        }
      }
    }

    traverse(tree);

    // Check for encoded strings and their entropy
    const encodedStrings =
      code.match(/(["'])(\\x[a-fA-F0-9]{2,}|[A-Za-z0-9+/=]{20,})\1/g) || [];
    const highEntropy = encodedStrings.filter((s) => entropy(s) > 4.5).length;

    // Check if whitespace is suspiciously low (minified code)
    const whitespaceRatio = (code.match(/\s/g) || []).length / code.length;
    const suspiciouslyCompressed = whitespaceRatio < 0.05;

    // Pattern-based checks
    const stringArrayPattern =
      /var\s+\w+\s*=\s*\[\s*(['"][^'"]+['"]\s*,?\s*){5,}\]/;
    const decodingFunctionPattern =
      /function\s*\(\w+,\s*\w+\)\s*\{\s*\w+\s*=\s*\w+\s*-\s*0x[0-9a-f]+;/;

    const usesStringArrayDecoder =
      stringArrayPattern.test(code) && decodingFunctionPattern.test(code);

    const decoderCalls = (code.match(/\w+\(0x[0-9a-f]+\)/g) || []).length;
    const decoderCallSpam = decoderCalls > 10;

    hexLiterals = (code.match(/0x[0-9a-fA-F]+/g) || []).length;

    if (/push\(.+shift\(\)/.test(code) && /_0x[a-f0-9]{4,}/.test(code)) {
      rotatingArrayDecoder = true;
    }

    const underscoreRatio =
      totalIdentifiers > 0 ? underscoreIdentifiers / totalIdentifiers : 0;

    // Weighted score system
    let score = 0;
    if (shortVars > 10) score += 0.1;
    if (evalCalls > 0) score += 0.25;
    if (highEntropy > 0) score += 0.2;
    if (suspiciouslyCompressed) score += 0.15;
    if (usesStringArrayDecoder) score += 0.25;
    if (decoderCallSpam) score += 0.15;
    if (deadCodeBlocks > 0) score += 0.05;
    if (suspiciousSwitches > 0) score += 0.1;
    if (suspiciousUnaryOps > 0) score += 0.2;
    if (hexLiterals > 5) score += 0.1;
    if (rotatingArrayDecoder) score += 0.1;
    if (underscoreRatio > 0.3) score += 0.1;

    const normalized = Math.min(score, 1.0);
    const threshold = 0.2;

    return { obfuscated: normalized >= threshold, confidence: normalized };
  } catch {
    return { obfuscated: true, confidence: 1.0 }; // syntax errors likely indicate obfuscation
  }
}

// CLI Usage
const inputCode = fs.readFileSync(process.argv[2], "utf8");
console.log(JSON.stringify(scoreObfuscation(inputCode), null, 2));
