export function classifyExecFileError(error) {
  if (typeof error === "object" && error !== null && typeof error.code === "number" && Number.isInteger(error.code) && "stdout" in error && "stderr" in error) {
    return { code: error.code, stdout: String(error.stdout), stderr: String(error.stderr) };
  }
  throw new Error("CLI process failed without a numeric exit code", { cause: error });
}
