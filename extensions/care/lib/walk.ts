// Shared AST walker over unbash's node union. Visits every Command node.
import type { Command, Node } from "unbash";

export function walkNode(node: Node, cb: (cmd: Command) => void): void {
  switch (node.type) {
    case "Command":
      cb(node);
      break;
    case "Statement":
      walkNode(node.command, cb);
      break;
    case "Pipeline":
      for (const c of node.commands) walkNode(c, cb);
      break;
    case "AndOr":
      for (const c of node.commands) walkNode(c, cb);
      break;
    case "CompoundList":
      for (const s of node.commands) walkNode(s, cb);
      break;
    case "Subshell":
      walkNode(node.body, cb);
      break;
    case "BraceGroup":
      walkNode(node.body, cb);
      break;
    case "If":
      walkNode(node.clause, cb);
      walkNode(node.then, cb);
      if (node.else) walkNode(node.else, cb);
      break;
    case "While":
      walkNode(node.clause, cb);
      walkNode(node.body, cb);
      break;
    case "For":
    case "Select":
    case "ArithmeticFor":
      walkNode(node.body, cb);
      break;
    case "Function":
      walkNode(node.body, cb);
      break;
    case "Case":
      for (const item of node.items) walkNode(item.body, cb);
      break;
    case "Coproc":
      walkNode(node.body, cb);
      break;
    default:
      break;
  }
}
