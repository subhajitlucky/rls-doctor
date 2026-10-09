import { describe, expect, it } from "vitest";
import {
  CHECK_TOOL_NAME,
  EXPLAIN_TOOL_NAME,
  MAX_TOOL_PAYLOAD_BYTES,
  PROBE_TOOL_NAME,
  PROVE_TOOL_NAME,
  REPAIR_TOOL_NAME,
  TOOL_DEFINITIONS,
  cutUtf8Safe,
} from "../src/mcp/tool-schemas.js";
import { errorToolResult, handleToolCall } from "../src/mcp/tools.js";

describe("mcp tool schemas", () => {
  it("advertises five read-only tools", () => {
    const names = TOOL_DEFINITIONS.map((tool) => tool.name).sort();
    expect(names).toEqual(
      [CHECK_TOOL_NAME, EXPLAIN_TOOL_NAME, PROBE_TOOL_NAME, PROVE_TOOL_NAME, REPAIR_TOOL_NAME].sort(),
    );
  });

  it("describes each tool as read-only", () => {
    for (const tool of TOOL_DEFINITIONS) {
      expect((tool.description ?? "").toLowerCase()).toContain("read-only");
      expect(tool.inputSchema).toBeDefined();
    }
  });

  it("requires appRoles for probe_access and table for explain_table", () => {
    const probe = TOOL_DEFINITIONS.find((tool) => tool.name === PROBE_TOOL_NAME);
    const explain = TOOL_DEFINITIONS.find((tool) => tool.name === EXPLAIN_TOOL_NAME);
    expect(probe?.inputSchema.required).toContain("appRoles");
    expect(explain?.inputSchema.required).toContain("table");
    const check = TOOL_DEFINITIONS.find((tool) => tool.name === CHECK_TOOL_NAME);
    expect(check?.inputSchema.required).toBeUndefined();
  });
});

describe("cutUtf8Safe", () => {
  it("returns short text unchanged", () => {
    expect(cutUtf8Safe("hello", 100)).toBe("hello");
  });

  it("truncates long text with a visible note", () => {
    const long = "a".repeat(MAX_TOOL_PAYLOAD_BYTES + 500);
    const out = cutUtf8Safe(long, MAX_TOOL_PAYLOAD_BYTES);
    expect(out.length).toBeLessThan(long.length);
    expect(out).toContain("[truncated:");
  });

  it("does not split a multi-byte sequence", () => {
    const text = "é".repeat(50);
    const out = cutUtf8Safe(text, 10);
    expect(out.startsWith("é")).toBe(true);
  });
});

describe("handleToolCall", () => {
  it("returns an error result for unknown tools", async () => {
    const result = await handleToolCall("not_a_tool", {});
    expect(result.isError).toBe(true);
  });

  it("returns an error when probe_access has no appRoles", async () => {
    process.env.DATABASE_URL = "postgresql://user:pass@localhost:5432/test";
    const result = await handleToolCall(PROBE_TOOL_NAME, { appRoles: [] });
    expect(result.isError).toBe(true);
    const text = result.content[0]!;
    expect(text.type === "text" ? text.text : "").toContain("appRoles");
  });

  it("sanitizes connection failures without echoing credentials", async () => {
    process.env.DATABASE_URL = "postgresql://secret-user:secret-pass@127.0.0.1:1/none";
    const result = await handleToolCall(CHECK_TOOL_NAME, {});
    expect(result.isError).toBe(true);
    const text = result.content[0]!;
    const body = text.type === "text" ? text.text : "";
    expect(body).not.toContain("secret-pass");
    expect(body).not.toContain("secret-user");
  });
});

describe("errorToolResult", () => {
  it("wraps non-Error values", () => {
    const result = errorToolResult("boom");
    expect(result.isError).toBe(true);
  });
});

describe("offline MCP tools", () => {
  it("proves isolation claims from schema files", async () => {
    const result = await handleToolCall(PROVE_TOOL_NAME, {
      schemaFiles: ["demo/unsafe-schema.sql"],
    });
    const artifact = JSON.parse(
      (result.content[0] as { text: string }).text,
    ) as { claims: { status: string }[]; digest: { value: string } };

    expect(artifact.claims.filter((claim) => claim.status === "witness")).toHaveLength(6);
    expect(artifact.digest.value).toHaveLength(64);
  });

  it("proposes a statically verified repair and explains non-applicability", async () => {
    const repaired = await handleToolCall(REPAIR_TOOL_NAME, {
      schemaFiles: ["demo/unsafe-schema.sql"],
      table: "orders",
    });
    const payload = JSON.parse(
      (repaired.content[0] as { text: string }).text,
    ) as { status: string; patch: string | null; verification: { resolved: string[] } };

    expect(payload.status).toBe("verified");
    expect(payload.patch).toContain("enable row level security");
    expect(payload.verification.resolved).toHaveLength(4);

    const notApplicable = await handleToolCall(REPAIR_TOOL_NAME, {
      schemaFiles: ["demo/unsafe-schema.sql"],
      table: "profiles",
    });
    const payload2 = JSON.parse(
      (notApplicable.content[0] as { text: string }).text,
    ) as { status: string };
    expect(payload2.status).toBe("not-applicable");
  });
});
