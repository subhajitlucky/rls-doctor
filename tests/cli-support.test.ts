import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";
import { formatCliError, resolveConnectionString } from "../src/cli-support.js";

const originalDatabaseUrl = process.env.DATABASE_URL;
const originalSupabaseDbUrl = process.env.SUPABASE_DB_URL;

afterEach(() => {
  restoreEnv("DATABASE_URL", originalDatabaseUrl);
  restoreEnv("SUPABASE_DB_URL", originalSupabaseDbUrl);
});

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

  it("does not redact short credentials inside safe diagnostic words", () => {
    const connectionString = "postgres://a:x@db.test/app";
    const output = formatCliError(
      new Error(
        `database app unavailable at db.test; user \"a\" authentication failed; password=x; ${connectionString}`
      ),
      connectionString
    );

    expect(output).toContain("database app unavailable at db.test");
    expect(output).not.toContain('user "a"');
    expect(output).not.toContain("password=x");
    expect(output).not.toContain(connectionString);
  });

  it("safely redacts credential tokens containing regex metacharacters", () => {
    const connectionString = "postgres://a%2Bb:x.*@db.test/app";
    const output = formatCliError(
      new Error(
        `user 'a+b' failed authentication with password: x.*; unrelated expression aZZb remains; ` +
          `${connectionString}; retry ${connectionString}`
      ),
      connectionString
    );

    expect(output).toContain("unrelated expression aZZb remains");
    expect(output).not.toContain("a+b");
    expect(output).not.toContain("x.*");
    expect(output).not.toContain(connectionString);
  });

  it("redacts raw @ characters in a known URL's user info while retaining the host", () => {
    const connectionString = "postgres://u:p@ss@db.test/app";
    const output = formatCliError(new Error(`could not connect to ${connectionString}`), connectionString);

    expect(output).toContain("db.test/app");
    expect(output).not.toContain(connectionString);
    expect(output).not.toContain("p@ss");
    expect(output).not.toContain("@ss@db.test");
  });

  it("redacts raw @ characters in generic URL user info without a resolved connection", () => {
    const output = formatCliError(
      "postgres://first@name:p@ss@db.test/app and postgresql://other:p@ss@db2.test/app"
    );

    expect(output).toContain("postgres://[redacted]@db.test/app");
    expect(output).toContain("postgresql://[redacted]@db2.test/app");
    expect(output).not.toContain("first@name");
    expect(output).not.toContain("p@ss");
  });

  it("handles long whitespace credential mismatches without pathological backtracking", () => {
    const message = `password${" ".repeat(10_000)}not-the-secret`;
    const startedAt = performance.now();

    expect(formatCliError(message, "postgres://user:secret@db.test/app")).toBe(message);
    expect(performance.now() - startedAt).toBeLessThan(2_000);
  });
});

describe("resolveConnectionString", () => {
  it("falls through blank explicit and DATABASE_URL values", () => {
    process.env.DATABASE_URL = "   ";
    process.env.SUPABASE_DB_URL = "postgres://fallback.test/app";

    expect(resolveConnectionString("")).toBe("postgres://fallback.test/app");
  });
});

describe("CLI error handlers", () => {
  it.each([
    ["check", []],
    ["explain", ["profiles"]]
  ])("sanitizes %s command stderr", (command, commandArguments) => {
    const connectionString = "postgres://a:x@127.0.0.1:1/app";
    const result = spawnSync(
      process.execPath,
      ["--import", "tsx", "src/cli.ts", command, ...commandArguments, "--connection", connectionString],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: { ...process.env, DATABASE_URL: "", SUPABASE_DB_URL: "" }
      }
    );

    expect(result.status).toBe(2);
    expect(result.stderr).toContain("rls-doctor:");
    expect(result.stderr).not.toContain(connectionString);
    expect(result.stderr).not.toContain("a:x");
  });
});

function restoreEnv(name: "DATABASE_URL" | "SUPABASE_DB_URL", value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}
