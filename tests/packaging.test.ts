import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { TOOL_DEFINITIONS } from "../src/mcp/tool-schemas.js";

const root = new URL("..", import.meta.url);

function readJson(relativePath: string): Record<string, unknown> {
  return JSON.parse(readFileSync(new URL(relativePath, root), "utf8")) as Record<string, unknown>;
}

describe("registry metadata", () => {
  it("keeps server.json in sync with package.json", () => {
    const pkg = readJson("package.json");
    const server = readJson("server.json");
    const packages = server["packages"] as Record<string, unknown>[];
    const transport = packages[0]?.["transport"] as Record<string, unknown>;

    expect(server["name"]).toBe(pkg["mcpName"]);
    expect(server["version"]).toBe(pkg["version"]);
    expect(packages[0]?.["identifier"]).toBe(pkg["name"]);
    expect(packages[0]?.["version"]).toBe(pkg["version"]);
    expect(transport["type"]).toBe("stdio");
  });

  it("ships the agent skill and agent docs in the published files", () => {
    const pkg = readJson("package.json");
    const files = pkg["files"] as string[];
    expect(files).toContain(".agents/skills/rls-doctor");
    expect(existsSync(new URL(".agents/skills/rls-doctor/SKILL.md", root))).toBe(true);
  });

  it("keeps the MCPB manifest tool list in sync with the tool schemas", () => {
    const source = readFileSync(new URL("scripts/build-mcpb.mjs", root), "utf8");
    for (const tool of TOOL_DEFINITIONS) {
      expect(source).toContain(`name: "${tool.name}"`);
    }
  });
});
