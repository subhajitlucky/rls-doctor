import type { Tool } from "@modelcontextprotocol/sdk/types.js";

export const CHECK_TOOL_NAME = "check_rls";
export const PROBE_TOOL_NAME = "probe_access";
export const EXPLAIN_TOOL_NAME = "explain_table";
export const PROVE_TOOL_NAME = "prove_isolation";
export const REPAIR_TOOL_NAME = "propose_repair";

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
  {
    name: PROVE_TOOL_NAME,
    description:
      "Prove row-isolation claims offline from SQL schema or migration files, with no " +
      "database connection: for each table, command, and role it returns proved " +
      "(with the ownership column), witness (with the reason), or undecided (outside " +
      "the sound decidable fragment). Read-only and offline.",
    inputSchema: {
      type: "object",
      properties: {
        schemaFiles: {
          type: "array",
          items: { type: "string" },
          description: "SQL schema or migration files to prove, in order.",
        },
        roles: {
          type: "array",
          items: { type: "string" },
          description: 'Application roles to prove isolation for. Defaults to ["authenticated"].',
        },
        table: {
          type: "string",
          description: "Optional table filter, schema-qualified (public.orders) or bare (orders).",
        },
      },
      required: ["schemaFiles"],
    },
  },
  {
    name: REPAIR_TOOL_NAME,
    description:
      "Generate a canonical repair for an RLS-disabled table and verify it statically " +
      "before returning it: the patch is only included when every target witness flips " +
      "to proved and no new medium+ finding appears. Read-only: never writes files and " +
      "never applies anything; the CLI `fix` command adds live shadow verification.",
    inputSchema: {
      type: "object",
      properties: {
        schemaFiles: {
          type: "array",
          items: { type: "string" },
          description: "SQL schema or migration files to repair, in order.",
        },
        table: {
          type: "string",
          description: "Table to repair, schema-qualified (public.orders) or bare (orders).",
        },
        roles: {
          type: "array",
          items: { type: "string" },
          description: 'Application roles the ownership policy applies to. Defaults to ["authenticated"].',
        },
      },
      required: ["schemaFiles", "table"],
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

export interface ProveToolArgs {
  schemaFiles: string[];
  roles: string[];
  table?: string;
}

export interface RepairToolArgs {
  schemaFiles: string[];
  table: string;
  roles: string[];
}

function requiredStringArray(value: unknown, field: string): string[] {
  const items = parseStringArray(value);
  if (items.length === 0) {
    throw new Error(`"${field}" is required and must contain at least one path.`);
  }
  return items;
}

export function parseProveToolArgs(input: unknown): ProveToolArgs {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new Error("prove_isolation arguments must be a JSON object.");
  }
  const args = input as Record<string, unknown>;
  const roles = parseStringArray(args.roles);
  const table = typeof args.table === "string" && args.table.trim().length > 0
    ? args.table.trim()
    : undefined;
  return {
    schemaFiles: requiredStringArray(args.schemaFiles, "schemaFiles"),
    roles: roles.length > 0 ? roles : ["authenticated"],
    ...(table === undefined ? {} : { table }),
  };
}

export function parseRepairToolArgs(input: unknown): RepairToolArgs {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new Error("propose_repair arguments must be a JSON object.");
  }
  const args = input as Record<string, unknown>;
  const table = typeof args.table === "string" ? args.table.trim() : "";
  if (table.length === 0) {
    throw new Error('"table" is required for propose_repair.');
  }
  const roles = parseStringArray(args.roles);
  return {
    schemaFiles: requiredStringArray(args.schemaFiles, "schemaFiles"),
    table,
    roles: roles.length > 0 ? roles : ["authenticated"],
  };
}

export function parseFormat(value: unknown): ToolFormat {
  return value === "json" ? "json" : "text";
}
