import type { Tool } from "@modelcontextprotocol/sdk/types.js";

export const CHECK_TOOL_NAME = "check_rls";
export const PROBE_TOOL_NAME = "probe_access";
export const EXPLAIN_TOOL_NAME = "explain_table";

export const MAX_TOOL_PAYLOAD_BYTES = 48 * 1024;

export type ToolFormat = "text" | "json";

export interface CheckToolArgs {
  connectionString?: string;
  schemas?: string[];
  appRoles?: string[];
  format?: ToolFormat;
}

export interface ProbeToolArgs {
  connectionString?: string;
  schemas?: string[];
  appRoles: string[];
  subjects?: string[];
  ownerColumns?: string[];
  format?: ToolFormat;
}

export interface ExplainToolArgs {
  connectionString?: string;
  table: string;
  format?: ToolFormat;
}

function schemaProps() {
  return {
    connectionString: {
      type: "string",
      description:
        "Postgres connection string. Falls back to DATABASE_URL or SUPABASE_DB_URL. " +
        "Prefer read-only credentials. Never commit or echo this value.",
    },
  };
}

export const TOOL_DEFINITIONS: readonly Tool[] = [
  {
    name: CHECK_TOOL_NAME,
    description:
      "Audit Postgres or Supabase Row Level Security posture from catalog metadata. " +
      "Reports disabled RLS, unconditional policies, missing WITH CHECK, reachable " +
      "TRUNCATE, disabled FORCE RLS, and broad default privileges. Read-only: it " +
      "never mutates the target database.",
    inputSchema: {
      type: "object",
      properties: {
        ...schemaProps(),
        schemas: {
          type: "array",
          items: { type: "string" },
          description: "Schema names to audit. Defaults to ['public'].",
        },
        appRoles: {
          type: "array",
          items: { type: "string" },
          description:
            "Additional application roles to treat as reachable identities, " +
            "for example app_user or web_user.",
        },
        format: {
          type: "string",
          enum: ["text", "json"],
          description: 'Report rendering. Defaults to "text".',
        },
      },
    },
  },
  {
    name: PROBE_TOOL_NAME,
    description:
      "Impersonate application roles in a rolled-back, read-only transaction and " +
      "report which rows they can actually read. Proves cross-tenant exposure that " +
      "catalog review alone cannot show. Never commits. Ask the user before " +
      "running this against a live database.",
    inputSchema: {
      type: "object",
      properties: {
        ...schemaProps(),
        schemas: {
          type: "array",
          items: { type: "string" },
          description: "Schema names to probe. Defaults to ['public'].",
        },
        appRoles: {
          type: "array",
          items: { type: "string" },
          description: "Application roles to impersonate with SET LOCAL ROLE. Required.",
        },
        subjects: {
          type: "array",
          items: { type: "string" },
          description:
            "User IDs to simulate through Supabase-compatible request.jwt.claims. " +
            "Use at least two distinct owners for a meaningful cross-tenant check.",
        },
        ownerColumns: {
          type: "array",
          items: { type: "string" },
          description:
            "Owner or tenant columns used for cross-owner checks. " +
            "Defaults to owner_id, user_id, tenant_id, account_id.",
        },
        format: {
          type: "string",
          enum: ["text", "json"],
          description: 'Report rendering. Defaults to "text".',
        },
      },
      required: ["appRoles"],
    },
  },
  {
    name: EXPLAIN_TOOL_NAME,
    description:
      "Explain the Row Level Security posture of one table: whether RLS and FORCE " +
      "RLS are on, which policies apply, what grants application roles hold, and " +
      "which risks apply. Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        ...schemaProps(),
        table: {
          type: "string",
          description: "Table reference, schema-qualified (public.profiles) or bare (profiles).",
        },
        format: {
          type: "string",
          enum: ["text", "json"],
          description: 'Report rendering. Defaults to "text".',
        },
      },
      required: ["table"],
    },
  },
];

export function cutUtf8Safe(text: string, maxBytes: number): string {
  if (Buffer.byteLength(text, "utf8") <= maxBytes) return text;
  const bytes = Buffer.from(text, "utf8");
  let end = maxBytes;
  while (end > 0 && (bytes[end]! & 0xc0) === 0x80) end -= 1;
  return bytes.subarray(0, end).toString("utf8") +
    "\n\n[truncated: response exceeded the tool payload limit]";
}

export function parseStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.length > 0);
}

export function parseFormat(value: unknown): ToolFormat {
  return value === "json" ? "json" : "text";
}
