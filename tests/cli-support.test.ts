import { describe, expect, it } from "vitest";
import { formatCliError } from "../src/cli-support.js";

describe("formatCliError", () => {
  it("redacts a connection URL and its credentials while preserving safe diagnostics", () => {
    const connectionString = "postgres://audit_user:very-secret@db.example.test:5432/app";
    const output = formatCliError(
      new Error(`connection to ${connectionString} failed: database \"app\" is unavailable`),
      connectionString
    );

    expect(output).toContain("db.example.test:5432/app");
    expect(output).toContain("database \"app\" is unavailable");
    expect(output).not.toContain(connectionString);
    expect(output).not.toContain("audit_user:very-secret");
    expect(output).not.toContain("very-secret");
  });

  it("redacts raw, decoded, and encoded forms of percent-encoded user info", () => {
    const connectionString = "postgresql://audit%5Fuser:very%2Dsecret@db.example.test:5432/app";
    const output = formatCliError(
      new Error(
        "authentication failed for audit%5Fuser:very%2Dsecret (audit_user:very-secret) at " +
          connectionString
      ),
      connectionString
    );

    expect(output).toContain("authentication failed");
    expect(output).toContain("db.example.test:5432/app");
    expect(output).not.toContain("audit%5Fuser:very%2Dsecret");
    expect(output).not.toContain("audit_user:very-secret");
    expect(output).not.toContain("very%2Dsecret");
    expect(output).not.toContain("very-secret");
  });

  it("redacts postgres user info even when no resolved connection is available", () => {
    const output = formatCliError(
      new Error("dial postgres://other-user:other-secret@db.example.test/app: connection refused")
    );

    expect(output).toContain("db.example.test/app: connection refused");
    expect(output).not.toContain("other-user");
    expect(output).not.toContain("other-secret");
  });

  it("preserves ordinary non-secret errors", () => {
    expect(formatCliError(new Error("--statement-timeout must be a positive number."))).toBe(
      "--statement-timeout must be a positive number."
    );
    expect(formatCliError("connection refused")).toBe("connection refused");
  });
});
