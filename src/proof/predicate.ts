/**
 * Decidable fragment for RLS policy predicates.
 *
 * Supported atoms:
 *   true / false
 *   <column> = auth.uid()          (ownership equality, either side)
 *
 * Combined with AND / OR. Anything else — NOT, subqueries, function calls,
 * casts, comparisons — is `undecided` with a reason, never a guess.
 *
 * A decision is one of:
 *   proved(column)   every row the predicate admits satisfies column = auth.uid()
 *   proved(null)     the predicate admits no rows (deny-all)
 *   witness(reason)  the predicate can admit a row outside the ownership
 *                    boundary, with the reason stated
 *   undecided(reason) outside the decidable fragment
 */

export type Decision =
  | { status: "proved"; column: string | null }
  | { status: "witness"; reason: string }
  | { status: "undecided"; reason: string };

type Expr =
  | { kind: "true" }
  | { kind: "false" }
  | { kind: "ownership"; column: string }
  | { kind: "and"; left: Expr; right: Expr }
  | { kind: "or"; left: Expr; right: Expr }
  | { kind: "unsupported"; reason: string };

const UID_PATTERN = /(?:\(\s*select\s+)?auth\.uid\(\)\s*\)?/iu;

function normalize(expression: string): string {
  let value = expression.trim();
  while (value.startsWith("(") && value.endsWith(")") && balanced(value.slice(1, -1))) {
    value = value.slice(1, -1).trim();
  }
  return value
    .replace(/\(\s*select\s+auth\.uid\(\)\s*\)/giu, "auth.uid()")
    .replace(/\s+/gu, " ")
    .trim();
}

function balanced(value: string): boolean {
  let depth = 0;
  for (const char of value) {
    if (char === "(") depth += 1;
    if (char === ")") depth -= 1;
    if (depth < 0) return false;
  }
  return depth === 0;
}

function splitTopLevel(value: string, operator: "or" | "and"): [string, string] | null {
  const upper = value.toUpperCase();
  const needle = operator === "or" ? " OR " : " AND ";
  let depth = 0;
  let quote: string | null = null;
  for (let index = 0; index <= value.length - needle.length; index += 1) {
    const char = value[index]!;
    if (quote !== null) {
      if (char === quote) quote = null;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === "(") depth += 1;
    if (char === ")") depth -= 1;
    if (depth === 0 && upper.slice(index, index + needle.length) === needle) {
      return [value.slice(0, index).trim(), value.slice(index + needle.length).trim()];
    }
  }
  return null;
}

function identifier(raw: string): string | null {
  const value = raw.trim();
  const match = /^(?:(?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)\s*\.\s*)*(?:"([^"]+)"|([A-Za-z_][A-Za-z0-9_$]*))$/u.exec(value);
  if (match === null) return null;
  return (match[1] ?? match[2] ?? "").toLowerCase();
}

function parse(expression: string): Expr {
  const value = normalize(expression);
  if (value.length === 0) return { kind: "unsupported", reason: "empty predicate" };

  const orParts = splitTopLevel(value, "or");
  if (orParts !== null) {
    return { kind: "or", left: parse(orParts[0]), right: parse(orParts[1]) };
  }
  const andParts = splitTopLevel(value, "and");
  if (andParts !== null) {
    return { kind: "and", left: parse(andParts[0]), right: parse(andParts[1]) };
  }

  if (/^true$/iu.test(value)) return { kind: "true" };
  if (/^false$/iu.test(value)) return { kind: "false" };

  const equality = splitEquality(value);
  if (equality !== null) {
    const [left, right] = equality;
    const leftIsUid = UID_PATTERN.test(left) && normalize(left).replace(UID_PATTERN, "") === "";
    const rightIsUid = UID_PATTERN.test(right) && normalize(right).replace(UID_PATTERN, "") === "";
    if (leftIsUid && !rightIsUid) {
      const column = identifier(right);
      return column === null
        ? { kind: "unsupported", reason: "ownership comparison is not a plain column" }
        : { kind: "ownership", column };
    }
    if (rightIsUid && !leftIsUid) {
      const column = identifier(left);
      return column === null
        ? { kind: "unsupported", reason: "ownership comparison is not a plain column" }
        : { kind: "ownership", column };
    }
    return { kind: "unsupported", reason: "equality does not compare a column with auth.uid()" };
  }

  return { kind: "unsupported", reason: `outside the decidable fragment: ${value}` };
}

function splitEquality(value: string): [string, string] | null {
  let depth = 0;
  let quote: string | null = null;
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index]!;
    if (quote !== null) {
      if (char === quote) quote = null;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === "(") depth += 1;
    if (char === ")") depth -= 1;
    if (char === "=" && depth === 0 && value[index + 1] !== "=" && value[index - 1] !== "=") {
      return [value.slice(0, index).trim(), value.slice(index + 1).trim()];
    }
  }
  return null;
}

function decideExpr(expr: Expr): Decision {
  switch (expr.kind) {
    case "true":
      return { status: "witness", reason: "the predicate admits every row" };
    case "false":
      return { status: "proved", column: null };
    case "ownership":
      return { status: "proved", column: expr.column };
    case "unsupported":
      return { status: "undecided", reason: expr.reason };
    case "and": {
      const left = decideExpr(expr.left);
      const right = decideExpr(expr.right);
      if (left.status === "proved" && left.column !== null) return left;
      if (right.status === "proved" && right.column !== null) return right;
      if (left.status === "proved") return left;
      if (right.status === "proved") return right;
      if (left.status === "witness" && right.status === "witness") {
        return { status: "witness", reason: "both sides of the conjunction admit every row" };
      }
      const undecided = [left, right].find((decision) => decision.status === "undecided");
      if (undecided !== undefined && undecided.status === "undecided") {
        return { status: "undecided", reason: undecided.reason };
      }
      return { status: "witness", reason: "the conjunction can admit rows outside the ownership boundary" };
    }
    case "or": {
      const left = decideExpr(expr.left);
      const right = decideExpr(expr.right);
      if (left.status === "proved" && left.column === null) return right;
      if (right.status === "proved" && right.column === null) return left;
      if (
        left.status === "proved" && right.status === "proved" &&
        left.column !== null && left.column === right.column
      ) {
        return left;
      }
      if (left.status === "witness" || right.status === "witness") {
        const witness = left.status === "witness" ? left : right;
        return {
          status: "witness",
          reason: witness.status === "witness" ? witness.reason : "a disjunct admits every row",
        };
      }
      if (left.status === "proved" || right.status === "proved") {
        return {
          status: "witness",
          reason: "a disjunct does not enforce the same ownership column",
        };
      }
      const undecided = left.status === "undecided" ? left : right;
      return {
        status: "undecided",
        reason: undecided.status === "undecided" ? undecided.reason : "disjunction is undecidable",
      };
    }
  }
}

export function decidePredicate(expression: string | null): Decision {
  if (expression === null) return { status: "proved", column: null };
  return decideExpr(parse(expression));
}
