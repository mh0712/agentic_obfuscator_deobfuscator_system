const esprima = require("esprima");

function analyzeJavaScriptComplexity(code) {
  let syntax;
  try {
    syntax = esprima.parseScript(code, { loc: true });
  } catch (e) {
    console.error(
      JSON.stringify({ error: `Syntax error in code: ${e.message}` })
    );
    process.exit(1);
  }

  let metrics = {
    lines: code.split("\n").length,
    functions: 0,
    classes: 0,
    variables: 0,
    strings: 0,
    literals: 0,
    booleans: 0,
    control_structures: 0,
    code_blocks: 0,
    nesting_depth: 0,
  };

  let currentDepth = 0;
  let maxDepth = 0;

  function traverse(node, depth = 0) {
    currentDepth = depth;
    if (depth > maxDepth) maxDepth = depth;

    switch (node.type) {
      case "FunctionDeclaration":
      case "FunctionExpression":
      case "ArrowFunctionExpression":
        metrics.functions++;
        metrics.code_blocks++;
        break;
      case "ClassDeclaration":
        metrics.classes++;
        metrics.code_blocks++;
        break;
      case "VariableDeclarator":
        metrics.variables++;
        break;
      case "Literal":
        metrics.literals++;
        if (typeof node.value === "string") metrics.strings++;
        if (typeof node.value === "boolean") metrics.booleans++;
        break;
      case "IfStatement":
      case "ForStatement":
      case "WhileStatement":
      case "DoWhileStatement":
      case "TryStatement":
      case "SwitchStatement":
        metrics.control_structures++;
        depth += 1;
        break;
    }

    for (let key in node) {
      if (node[key] && typeof node[key] === "object") {
        if (Array.isArray(node[key])) {
          node[key].forEach((child) => child && traverse(child, depth));
        } else {
          traverse(node[key], depth);
        }
      }
    }
  }

  traverse(syntax);

  metrics.nesting_depth = maxDepth;
  metrics.identifiers = metrics.variables + metrics.functions + metrics.classes;

  const applicability_flags = {
    min_identifiers: metrics.identifiers >= 2,
    min_functions: metrics.functions >= 1,
    min_string_literals: metrics.strings >= 1,
    min_literals: metrics.literals >= 2,
    min_code_blocks: metrics.code_blocks >= 2,
    min_control_structures: metrics.control_structures >= 1,
    min_boolean_expressions: metrics.booleans >= 1,
    max_nesting_depth: metrics.nesting_depth <= 5,
  };

  console.log(
    JSON.stringify(
      {
        complexity_metrics: metrics,
        applicability_flags: applicability_flags,
      },
      null,
      2
    )
  );
}

// === Read code from stdin ===
let code = "";
process.stdin.setEncoding("utf8");

process.stdin.on("data", function (chunk) {
  code += chunk;
});

process.stdin.on("end", function () {
  analyzeJavaScriptComplexity(code);
});
