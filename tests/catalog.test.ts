import { describe, expect, it } from "vitest";
import { normalizePolicyRoles } from "../src/db/catalog.js";

describe("normalizePolicyRoles", () => {
  it("keeps native Postgres text arrays", () => {
    expect(normalizePolicyRoles(["authenticated", "service_role"])).toEqual([
      "authenticated",
      "service_role"
    ]);
  });

  it("parses text-array strings returned by some pg catalog queries", () => {
    expect(normalizePolicyRoles("{public,authenticated}")).toEqual(["public", "authenticated"]);
  });

  it("parses quoted text-array strings", () => {
    expect(normalizePolicyRoles('{"anon","authenticated"}')).toEqual(["anon", "authenticated"]);
  });
});
