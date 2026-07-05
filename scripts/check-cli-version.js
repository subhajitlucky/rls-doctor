#!/usr/bin/env node
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const { stdout } = await execFileAsync("node", ["dist/cli.js", "--version"], {
  cwd: new URL("..", import.meta.url)
});
const actual = stdout.trim();

if (actual !== packageJson.version) {
  console.error(`CLI version mismatch: expected ${packageJson.version}, got ${actual}`);
  process.exit(1);
}

console.log(`CLI version matches package.json: ${actual}`);
