import { createRequire } from "node:module";
import { Server } from "@modelcontextprotocol/sdk/server";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { errorToolResult, handleToolCall } from "./tools.js";
import { TOOL_DEFINITIONS } from "./tool-schemas.js";

export const MCP_SERVER_NAME = "rls-doctor";

const require = createRequire(import.meta.url);
function packageVersion(): string {
  for (const candidate of ["../package.json", "../../package.json"]) {
    try {
      return (require(candidate) as { version: string }).version;
    } catch {
      // Try the next layout: bundled output lives one level shallower.
    }
  }
  return "0.0.0";
}
export const MCP_SERVER_VERSION = packageVersion();

const SERVER_INSTRUCTIONS = [
  "RLS Doctor audits Postgres and Supabase Row Level Security and returns",
  "deterministic findings for coding agents.",
  "check_rls reads catalog metadata. probe_access impersonates application",
  "roles in a rolled-back read-only transaction. explain_table covers one table.",
  "prove_isolation and propose_repair work offline from SQL files and never",
  "connect to a database. Every tool is read-only against the target database",
  "and never mutates it. Ask the user before connecting to a live database.",
  "Never print connection strings.",
].join(" ");

export function createMcpServer(): Server {
  const server = new Server(
    { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
    { capabilities: { tools: {} }, instructions: SERVER_INSTRUCTIONS },
  );
  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: [...TOOL_DEFINITIONS],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
      return await handleToolCall(request.params.name, request.params.arguments);
    } catch (error) {
      return errorToolResult(error);
    }
  });
  return server;
}

export async function startMcpStdioServer(): Promise<void> {
  const server = createMcpServer();
  await server.connect(new StdioServerTransport());
}
