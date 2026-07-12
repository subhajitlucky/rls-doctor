import { describe, expect, it } from "vitest";
import { classifyExecFileError } from "../scripts/integration-helpers.js";

describe("classifyExecFileError", () => {
  it("accepts a numeric CLI exit code", () => {
    expect(classifyExecFileError({ code: 1, stdout: "report", stderr: "" })).toEqual({
      code: 1,
      stdout: "report",
      stderr: ""
    });
  });

  it.each([
    { code: null, stdout: "", stderr: "", signal: "SIGTERM" },
    { code: "ENOBUFS", stdout: "", stderr: "" },
    { code: Number.NaN, stdout: "", stderr: "" },
    { stdout: "", stderr: "" }
  ])("rejects infrastructure failures %#", (error) => {
    expect(() => classifyExecFileError(error)).toThrow("CLI process failed without a numeric exit code");
  });
});
