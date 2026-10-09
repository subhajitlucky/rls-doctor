import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { DEMO_REPLAY_OUTPUT } from "../src/demo/fixture.js";
import { runDemo } from "../src/demo/runner.js";
import { DEMO_UNSAFE_SCHEMA_SQL } from "../src/demo/schema.js";

describe("demo", () => {
  it("keeps the embedded demo schema in sync with demo/unsafe-schema.sql", async () => {
    const file = await readFile("demo/unsafe-schema.sql", "utf8");
    expect(DEMO_UNSAFE_SCHEMA_SQL).toBe(file);
  });

  it("falls back to a recorded run when Docker is unavailable", async () => {
    const outcome = await runDemo({ isDockerAvailable: async () => false });

    expect(outcome.live).toBe(false);
    expect(outcome.output).toContain("Docker was not found on this machine.");
    expect(outcome.output).toContain("Showing a recorded run instead.");
    expect(outcome.output).toContain("probe-cross-owner-read");
    expect(DEMO_REPLAY_OUTPUT).toContain("RLS Score:");
  });

  it("falls back when the live demo fails and redacts credentials", async () => {
    const outcome = await runDemo({
      isDockerAvailable: async () => true,
      runLiveDemo: async () => {
        throw new Error("boom postgres:postgres@127.0.0.1");
      },
    });

    expect(outcome.live).toBe(false);
    expect(outcome.output).toContain("boom [redacted]@127.0.0.1");
    expect(outcome.output).not.toContain("postgres:postgres");
  });

  it("returns live output when the live demo succeeds", async () => {
    const outcome = await runDemo({
      isDockerAvailable: async () => true,
      runLiveDemo: async () => "LIVE\n",
    });

    expect(outcome).toEqual({ output: "LIVE\n", live: true });
  });
});
