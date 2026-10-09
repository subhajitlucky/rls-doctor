import type {
  CatalogSnapshot,
  DefaultPrivilegeSnapshot,
  PolicyCommand,
  PolicySnapshot,
  RelationPrivilege,
  RelationPrivilegeSnapshot,
  RoleMembershipSnapshot,
  RoleSnapshot,
  SchemaPrivilegeSnapshot,
  TableSnapshot
} from "./types.js";

export interface ParsedSchemaFile {
  snapshot: CatalogSnapshot;
  schemas: string[];
  limitations: string[];
}

const IDENTIFIER = `(?:"(?:[^"]|"")*"|[A-Za-z_][A-Za-z0-9_$]*)`;
const QUALIFIED = `(?:(${IDENTIFIER})\\s*\\.\\s*)?(${IDENTIFIER})`;
const RELATION_PRIVILEGES: RelationPrivilege[] = [
  "SELECT",
  "INSERT",
  "UPDATE",
  "DELETE",
  "TRUNCATE",
  "REFERENCES",
  "TRIGGER"
];
const MAX_LIMITATIONS = 20;
const OWNER_UNKNOWN = "current_user";

const IGNORED_STATEMENT = new RegExp(
  "^(?:" +
    "create\\s+or\\s+replace\\s+(?:function|procedure|view|trigger)|" +
    "create\\s+(?:extension|function|procedure|index|unique\\s+index|view|materialized\\s+view|sequence|type|domain|trigger|publication|subscription|collation)|" +
    "alter\\s+(?:extension|function|procedure|index|sequence|type|domain|trigger|publication|subscription)|" +
    "comment\\s+on|set\\s|reset\\s|select\\s|insert\\s|update\\s|delete\\s|begin\\b|commit\\b|rollback\\b|start\\s+transaction|analyze\\b|vacuum\\b|listen\\b|notify\\b|grant\\s+execute|revoke\\s+execute" +
  ")",
  "i"
);

export function parseSchemaSql(sql: string): ParsedSchemaFile {
  const state = new SchemaFileState();

  for (const statement of splitStatements(sql.replace(/^\uFEFF/u, ""))) {
    state.apply(statement);
  }

  return {
    snapshot: state.snapshot(),
    schemas: state.schemas(),
    limitations: state.limitations
  };
}

class SchemaFileState {
  private readonly tables = new Map<string, TableSnapshot>();
  private readonly policies = new Map<string, PolicySnapshot>();
  private readonly relationPrivileges = new Map<string, RelationPrivilegeSnapshot>();
  private readonly defaultPrivileges = new Map<string, DefaultPrivilegeSnapshot>();
  private readonly schemaPrivileges = new Map<string, SchemaPrivilegeSnapshot>();
  private readonly roles = new Map<string, RoleSnapshot>();
  private readonly memberships = new Map<string, RoleMembershipSnapshot>();
  private readonly knownSchemas = new Set<string>();
  readonly limitations: string[] = [];

  private key(schema: string, table: string): string {
    return `${schema}\0${table}`;
  }

  apply(statement: string): void {
    const text = statement.trim();
    if (text.length === 0) return;

    if (this.applyDrop(text)) return;
    if (this.applyCreate(text)) return;
    if (this.applyAlter(text)) return;
    if (this.applyGrant(text)) return;
    if (this.applyRevoke(text)) return;
    if (this.applyDoBlock(text)) return;
    if (IGNORED_STATEMENT.test(text)) return;

    this.addLimitation(`Unsupported statement was not evaluated offline: ${excerpt(text)}`);
  }

  snapshot(): CatalogSnapshot {
    return {
      tables: [...this.tables.values()].sort(compareTables),
      policies: [...this.policies.values()].sort(comparePolicies),
      relationPrivileges: [...this.relationPrivileges.values()].sort(compareRelationPrivileges),
      defaultPrivileges: [...this.defaultPrivileges.values()].sort(compareDefaultPrivileges),
      schemaPrivileges: [...this.schemaPrivileges.values()].sort(compareSchemaPrivileges),
      roles: [...this.roles.values()].sort((a, b) => a.name.localeCompare(b.name)),
      roleMemberships: [...this.memberships.values()].sort((a, b) =>
        `${a.member}\0${a.role}`.localeCompare(`${b.member}\0${b.role}`)
      )
    };
  }

  schemas(): string[] {
    const schemas = new Set(this.knownSchemas);
    for (const table of this.tables.values()) schemas.add(table.schema);
    for (const policy of this.policies.values()) schemas.add(policy.schema);
    for (const privilege of this.relationPrivileges.values()) schemas.add(privilege.schema);
    for (const privilege of this.schemaPrivileges.values()) schemas.add(privilege.schema);
    for (const privilege of this.defaultPrivileges.values()) {
      if (privilege.schema !== null) schemas.add(privilege.schema);
    }
    return [...schemas].sort();
  }

  private addLimitation(message: string): void {
    if (this.limitations.length >= MAX_LIMITATIONS) {
      const overflow = `and more unsupported statements were omitted`;
      if (!this.limitations.includes(overflow)) this.limitations.push(overflow);
      return;
    }
    if (!this.limitations.includes(message)) this.limitations.push(message);
  }

  private table(schema: string, name: string): TableSnapshot {
    const key = this.key(schema, name);
    const existing = this.tables.get(key);
    if (existing !== undefined) return existing;
    const table: TableSnapshot = {
      schema,
      name,
      rlsEnabled: false,
      forceRls: false,
      isPartitioned: false,
      estimatedRows: null
    };
    this.tables.set(key, table);
    this.knownSchemas.add(schema);
    return table;
  }

  private applyDrop(text: string): boolean {
    const schemaDrop = new RegExp(`^drop\\s+schema\\s+(?:if\\s+exists\\s+)?(${IDENTIFIER})`, "i").exec(text);
    if (schemaDrop !== null) {
      this.dropSchema(parseIdentifier(schemaDrop[1]!));
      return true;
    }
    const tableDrop = new RegExp(
      `^drop\\s+table\\s+(?:if\\s+exists\\s+)?(.+?)(?:\\s+cascade|\\s+restrict)?$`,
      "i"
    ).exec(text);
    if (tableDrop !== null) {
      for (const reference of splitList(tableDrop[1]!)) {
        const parsed = parseQualified(reference);
        if (parsed === undefined) continue;
        this.dropTable(parsed.schema ?? "public", parsed.name);
      }
      return true;
    }
    const policyDrop = new RegExp(
      `^drop\\s+policy\\s+(?:if\\s+exists\\s+)?(${IDENTIFIER})\\s+on\\s+${QUALIFIED}`,
      "i"
    ).exec(text);
    if (policyDrop !== null) {
      const name = parseIdentifier(policyDrop[1]!);
      const schema = policyDrop[2] === undefined ? "public" : parseIdentifier(policyDrop[2]);
      const table = parseIdentifier(policyDrop[3]!);
      this.policies.delete(this.policyKey(schema, table, name));
      return true;
    }
    return false;
  }

  private applyCreate(text: string): boolean {
    const schema = new RegExp(`^create\\s+schema\\s+(?:if\\s+not\\s+exists\\s+)?${IDENTIFIER}`, "i").exec(text);
    if (schema !== null) {
      this.knownSchemas.add(parseIdentifier(schema[0].split(/\s+/u).pop()!));
      return true;
    }

    const policy = new RegExp(
      `^create\\s+policy\\s+(?:if\\s+not\\s+exists\\s+)?(${IDENTIFIER})\\s+on\\s+${QUALIFIED}([\\s\\S]*)$`,
      "i"
    ).exec(text);
    if (policy !== null) {
      const name = parseIdentifier(policy[1]!);
      const schema = policy[2] === undefined ? "public" : parseIdentifier(policy[2]);
      const table = parseIdentifier(policy[3]!);
      const rest = policy[4] ?? "";
      const permissive = !/^\s*as\s+restrictive\b/iu.test(rest);
      const commandMatch = /(?:^|\s)for\s+(all|select|insert|update|delete)\b/iu.exec(rest);
      const command = (commandMatch?.[1]?.toUpperCase() ?? "ALL") as PolicyCommand;
      const toMatch = /(?:^|\s)to\s+([\s\S]*?)(?=\s+using\b|\s+with\s+check\b|$)/iu.exec(rest);
      const roles = toMatch === null ? ["public"] : splitList(toMatch[1]!).map(parseIdentifier);
      const usingMatch = /(?:^|\s)using\s*\(/iu.exec(rest);
      const checkMatch = /(?:^|\s)with\s+check\s*\(/iu.exec(rest);
      const policySnapshot: PolicySnapshot = {
        schema,
        table,
        name,
        command,
        permissive,
        roles,
        usingExpression: usingMatch === null
          ? null
          : readParenthesized(rest, usingMatch.index + usingMatch[0].length - 1),
        checkExpression: checkMatch === null
          ? null
          : readParenthesized(rest, checkMatch.index + checkMatch[0].length - 1)
      };
      this.policies.set(this.policyKey(schema, table, name), policySnapshot);
      return true;
    }

    const table = new RegExp(
      `^create\\s+table\\s+(?:if\\s+not\\s+exists\\s+)?${QUALIFIED}`,
      "i"
    ).exec(text);
    if (table !== null) {
      const schema = table[1] === undefined ? "public" : parseIdentifier(table[1]);
      const name = parseIdentifier(table[2]!);
      const snapshot = this.table(schema, name);
      if (/\bpartition\s+by\b/iu.test(text)) {
        this.tables.set(this.key(schema, name), { ...snapshot, isPartitioned: true });
      }
      return true;
    }

    const role = new RegExp(`^create\\s+(?:role|user)\\s+(${IDENTIFIER})([\\s\\S]*)$`, "i").exec(text);
    if (role !== null) {
      this.upsertRole(parseIdentifier(role[1]!), role[2] ?? "");
      return true;
    }

    return false;
  }

  private applyAlter(text: string): boolean {
    const rls = new RegExp(
      `^alter\\s+table\\s+(?:only\\s+)?${QUALIFIED}\\s+(enable|disable)\\s+row\\s+level\\s+security`,
      "i"
    ).exec(text);
    if (rls !== null) {
      const schema = rls[1] === undefined ? "public" : parseIdentifier(rls[1]);
      const name = parseIdentifier(rls[2]!);
      const snapshot = this.table(schema, name);
      this.tables.set(this.key(schema, name), {
        ...snapshot,
        rlsEnabled: rls[3]!.toLowerCase() === "enable"
      });
      return true;
    }

    const forceRls = new RegExp(
      `^alter\\s+table\\s+(?:only\\s+)?${QUALIFIED}\\s+(force|no\\s+force)\\s+row\\s+level\\s+security`,
      "i"
    ).exec(text);
    if (forceRls !== null) {
      const schema = forceRls[1] === undefined ? "public" : parseIdentifier(forceRls[1]);
      const name = parseIdentifier(forceRls[2]!);
      const snapshot = this.table(schema, name);
      this.tables.set(this.key(schema, name), {
        ...snapshot,
        forceRls: forceRls[3]!.toLowerCase().startsWith("force")
      });
      return true;
    }

    const owner = new RegExp(
      `^alter\\s+table\\s+(?:only\\s+)?${QUALIFIED}\\s+owner\\s+to\\s+(${IDENTIFIER})`,
      "i"
    ).exec(text);
    if (owner !== null) {
      const schema = owner[1] === undefined ? "public" : parseIdentifier(owner[1]);
      const name = parseIdentifier(owner[2]!);
      const snapshot = this.table(schema, name);
      this.tables.set(this.key(schema, name), { ...snapshot, owner: parseIdentifier(owner[3]!) });
      return true;
    }

    const defaultPrivileges = new RegExp(
      `^alter\\s+default\\s+privileges(?:\\s+in\\s+schema\\s+${IDENTIFIER})?(?:\\s+for\\s+(?:role|user)\\s+${IDENTIFIER})?\\s+(grant|revoke)\\s+(.+?)\\s+on\\s+tables\\s+(?:to|from)\\s+(.+)$`,
      "i"
    ).exec(text);
    if (defaultPrivileges !== null) {
      const schemaMatch = /in\s+schema\s+((?:"(?:[^"]|"")*"|[A-Za-z_][A-Za-z0-9_$]*))/iu.exec(text);
      const schema = schemaMatch === null ? null : parseIdentifier(schemaMatch[1]!);
      const forRole = /for\s+(?:role|user)\s+((?:"(?:[^"]|"")*"|[A-Za-z_][A-Za-z0-9_$]*))/iu.exec(text);
      const owner = forRole === null ? OWNER_UNKNOWN : parseIdentifier(forRole[1]!);
      const grant = defaultPrivileges[1]!.toLowerCase() === "grant";
      const privileges = parsePrivilegeNames(defaultPrivileges[2]!);
      const roles = splitList(defaultPrivileges[3]!).map(parseIdentifier);
      const grantable = /\bwith\s+grant\s+option\b/iu.test(text);
      for (const privilege of privileges) {
        for (const grantee of roles) {
          const entry: DefaultPrivilegeSnapshot = {
            schema,
            owner,
            grantee,
            objectType: "TABLE",
            privilege,
            grantable
          };
          const key = defaultPrivilegeKey(entry);
          if (grant) this.defaultPrivileges.set(key, entry);
          else this.defaultPrivileges.delete(key);
        }
      }
      return true;
    }

    const policyAlter = new RegExp(`^alter\\s+policy\\b`, "i").test(text);
    if (policyAlter) {
      this.addLimitation("ALTER POLICY statements were not evaluated offline.");
      return true;
    }

    const role = new RegExp(`^alter\\s+(?:role|user)\\s+(${IDENTIFIER})([\\s\\S]*)$`, "i").exec(text);
    if (role !== null) {
      this.upsertRole(parseIdentifier(role[1]!), role[2] ?? "");
      return true;
    }

    return false;
  }

  private applyGrant(text: string): boolean {
    if (/^grant\s+execute\b/iu.test(text)) return true;

    const schemaGrant = new RegExp(
      `^grant\\s+(.+?)\\s+on\\s+schema\\s+(${IDENTIFIER})\\s+to\\s+(.+?)(?:\\s+with\\s+grant\\s+option)?$`,
      "i"
    ).exec(text);
    if (schemaGrant !== null) {
      const schemaName = parseIdentifier(schemaGrant[2]!);
      const privileges = parsePrivilegeNames(schemaGrant[1]!);
      if (privileges.some((privilege) => !["USAGE", "CREATE"].includes(privilege))) {
        this.addLimitation(`Unsupported schema grant was not evaluated offline: ${excerpt(text)}`);
        return true;
      }
      const grantable = /\bwith\s+grant\s+option\b/iu.test(text);
      for (const privilege of privileges) {
        for (const grantee of splitList(schemaGrant[3]!).map(parseIdentifier)) {
          const entry: SchemaPrivilegeSnapshot = {
            schema: schemaName,
            grantor: OWNER_UNKNOWN,
            grantee,
            privilege: privilege as "USAGE" | "CREATE",
            grantable
          };
          this.schemaPrivileges.set(schemaPrivilegeKey(entry), entry);
        }
      }
      this.knownSchemas.add(schemaName);
      return true;
    }

    const allTables = new RegExp(
      `^grant\\s+(.+?)\\s+on\\s+all\\s+tables\\s+in\\s+schema\\s+${IDENTIFIER}\\s+to\\s+(.+?)(?:\\s+with\\s+grant\\s+option)?$`,
      "i"
    ).exec(text);
    if (allTables !== null) {
      const schemaMatch = /in\s+schema\s+((?:"(?:[^"]|"")*"|[A-Za-z_][A-Za-z0-9_$]*))/iu.exec(text);
      const schema = parseIdentifier(schemaMatch![1]!);
      const privileges = parsePrivilegeNames(allTables[1]!);
      const roles = splitList(allTables[2]!).map(parseIdentifier);
      const grantable = /\bwith\s+grant\s+option\b/iu.test(text);
      for (const table of this.tables.values()) {
        if (table.schema !== schema) continue;
        for (const privilege of privileges) {
          if (!isRelationPrivilege(privilege)) continue;
          for (const grantee of roles) {
            const entry: RelationPrivilegeSnapshot = {
              schema,
              table: table.name,
              grantor: OWNER_UNKNOWN,
              grantee,
              privilege,
              grantable
            };
            this.relationPrivileges.set(relationPrivilegeKey(entry), entry);
          }
        }
      }
      return true;
    }

    const tableGrant = new RegExp(
      `^grant\\s+(.+?)\\s+on\\s+(?:table\\s+)?(.+?)\\s+to\\s+(.+?)(?:\\s+with\\s+grant\\s+option)?$`,
      "i"
    ).exec(text);
    if (tableGrant !== null) {
      const privileges = parsePrivilegeNames(tableGrant[1]!);
      if (privileges.some((privilege) => !isRelationPrivilege(privilege))) return true;
      const roles = splitList(tableGrant[3]!).map(parseIdentifier);
      const grantable = /\bwith\s+grant\s+option\b/iu.test(text);
      for (const reference of splitList(tableGrant[2]!)) {
        const parsed = parseQualified(reference);
        if (parsed === undefined) {
          this.addLimitation(`Unsupported table grant target was not evaluated offline: ${excerpt(reference)}`);
          continue;
        }
        const schema = parsed.schema ?? "public";
        const table = parsed.name;
        this.table(schema, table);
        for (const privilege of privileges) {
          for (const grantee of roles) {
            const entry: RelationPrivilegeSnapshot = {
              schema,
              table,
              grantor: OWNER_UNKNOWN,
              grantee,
              privilege: privilege as RelationPrivilege,
              grantable
            };
            this.relationPrivileges.set(relationPrivilegeKey(entry), entry);
          }
        }
      }
      return true;
    }

    const membership = new RegExp(`^grant\\s+(.+?)\\s+to\\s+(.+?)(?:\\s+with\\s+([\\s\\S]+))?$`, "i").exec(text);
    if (membership !== null) {
      const options = membership[3] ?? "";
      const inheritOption = !/\binherit\s+false\b/iu.test(options);
      const setOption = !/\bset\s+false\b/iu.test(options);
      for (const role of splitList(membership[1]!).map(parseIdentifier)) {
        for (const member of splitList(membership[2]!).map(parseIdentifier)) {
          this.ensureRole(role);
          this.ensureRole(member);
          const entry: RoleMembershipSnapshot = { role, member, inheritOption, setOption };
          this.memberships.set(`${member}\0${role}`, entry);
        }
      }
      return true;
    }

    return false;
  }

  private applyRevoke(text: string): boolean {
    const schemaRevoke = new RegExp(
      `^revoke\\s+(.+?)\\s+on\\s+schema\\s+(${IDENTIFIER})\\s+from\\s+(.+?)(?:\\s+cascade|\\s+restrict)?$`,
      "i"
    ).exec(text);
    if (schemaRevoke !== null) {
      const schemaName = parseIdentifier(schemaRevoke[2]!);
      const privileges = parsePrivilegeNames(schemaRevoke[1]!);
      for (const privilege of privileges) {
        for (const grantee of splitList(schemaRevoke[3]!).map(parseIdentifier)) {
          this.schemaPrivileges.delete(schemaPrivilegeKey({
            schema: schemaName,
            grantor: OWNER_UNKNOWN,
            grantee,
            privilege: privilege as "USAGE" | "CREATE",
            grantable: false
          }));
        }
      }
      return true;
    }

    const tableRevoke = new RegExp(
      `^revoke\\s+(.+?)\\s+on\\s+(?:table\\s+)?(.+?)\\s+from\\s+(.+?)(?:\\s+cascade|\\s+restrict)?$`,
      "i"
    ).exec(text);
    if (tableRevoke !== null) {
      const privileges = parsePrivilegeNames(tableRevoke[1]!);
      const roles = splitList(tableRevoke[3]!).map(parseIdentifier);
      for (const reference of splitList(tableRevoke[2]!)) {
        const parsed = parseQualified(reference);
        if (parsed === undefined) continue;
        const schema = parsed.schema ?? "public";
        for (const privilege of privileges) {
          if (!isRelationPrivilege(privilege)) continue;
          for (const grantee of roles) {
            this.relationPrivileges.delete(relationPrivilegeKey({
              schema,
              table: parsed.name,
              grantor: OWNER_UNKNOWN,
              grantee,
              privilege,
              grantable: false
            }));
          }
        }
      }
      return true;
    }

    const membershipRevoke = new RegExp(`^revoke\\s+(.+?)\\s+from\\s+(.+?)(?:\\s+cascade|\\s+restrict)?$`, "i").exec(text);
    if (membershipRevoke !== null) {
      for (const role of splitList(membershipRevoke[1]!).map(parseIdentifier)) {
        for (const member of splitList(membershipRevoke[2]!).map(parseIdentifier)) {
          this.memberships.delete(`${member}\0${role}`);
        }
      }
      return true;
    }

    return false;
  }

  private applyDoBlock(text: string): boolean {
    if (!/^do\b/iu.test(text)) return false;

    const body = dollarQuotedBody(text);
    if (body === null) {
      this.addLimitation("A DO block could not be evaluated offline.");
      return true;
    }

    let parsedRole = false;
    const roleExpression = new RegExp(`\\bcreate\\s+(?:role|user)\\s+(${IDENTIFIER})([\\s\\S]*?)(?=;|$)`, "giu");
    for (const match of body.matchAll(roleExpression)) {
      this.upsertRole(parseIdentifier(match[1]!), match[2] ?? "");
      parsedRole = true;
    }

    this.addLimitation(
      parsedRole
        ? "A DO block was parsed as unconditional role definitions; its conditional logic was not evaluated."
        : "A DO block was not evaluated offline."
    );
    return true;
  }

  private upsertRole(name: string, attributes: string): void {
    const existing = this.roles.get(name) ?? { name, superuser: false, bypassRls: false, inherits: true };
    this.roles.set(name, {
      name,
      superuser: attributeValue(attributes, "superuser", existing.superuser),
      bypassRls: attributeValue(attributes, "bypassrls", existing.bypassRls),
      inherits: attributeValue(attributes, "inherit", existing.inherits)
    });
  }

  private ensureRole(name: string): void {
    if (!this.roles.has(name)) {
      this.roles.set(name, { name, superuser: false, bypassRls: false, inherits: true });
    }
  }

  private policyKey(schema: string, table: string, name: string): string {
    return `${schema}\0${table}\0${name}`;
  }

  private dropTable(schema: string, name: string): void {
    this.tables.delete(this.key(schema, name));
    for (const key of [...this.policies.keys()]) {
      if (key.startsWith(`${schema}\0${name}\0`)) this.policies.delete(key);
    }
    for (const key of [...this.relationPrivileges.keys()]) {
      if (key.startsWith(`${schema}\0${name}\0`)) this.relationPrivileges.delete(key);
    }
  }

  private dropSchema(schema: string): void {
    for (const key of [...this.tables.keys()]) {
      if (key.startsWith(`${schema}\0`)) this.tables.delete(key);
    }
    for (const key of [...this.policies.keys()]) {
      if (key.startsWith(`${schema}\0`)) this.policies.delete(key);
    }
    for (const key of [...this.relationPrivileges.keys()]) {
      if (key.startsWith(`${schema}\0`)) this.relationPrivileges.delete(key);
    }
    for (const key of [...this.schemaPrivileges.keys()]) {
      if (key.startsWith(`${schema}\0`)) this.schemaPrivileges.delete(key);
    }
    for (const key of [...this.defaultPrivileges.keys()]) {
      if (key.startsWith(`${schema}\0`)) this.defaultPrivileges.delete(key);
    }
    this.knownSchemas.delete(schema);
  }
}

export function splitStatements(sql: string): string[] {
  const statements: string[] = [];
  let current = "";
  let index = 0;

  while (index < sql.length) {
    const char = sql[index]!;

    if (char === "'") {
      const end = skipQuoted(sql, index, "'");
      current += sql.slice(index, end);
      index = end;
      continue;
    }
    if (char === '"') {
      const end = skipQuoted(sql, index, '"');
      current += sql.slice(index, end);
      index = end;
      continue;
    }
    if (char === "-" && sql[index + 1] === "-") {
      const end = sql.indexOf("\n", index);
      index = end === -1 ? sql.length : end;
      continue;
    }
    if (char === "/" && sql[index + 1] === "*") {
      let depth = 1;
      index += 2;
      while (index < sql.length && depth > 0) {
        if (sql[index] === "/" && sql[index + 1] === "*") {
          depth += 1;
          index += 2;
        } else if (sql[index] === "*" && sql[index + 1] === "/") {
          depth -= 1;
          index += 2;
        } else {
          index += 1;
        }
      }
      continue;
    }
    if (char === "$") {
      const tag = /^\$[A-Za-z0-9_]*\$/u.exec(sql.slice(index));
      if (tag !== null) {
        const close = sql.indexOf(tag[0], index + tag[0].length);
        const end = close === -1 ? sql.length : close + tag[0].length;
        current += sql.slice(index, end);
        index = end;
        continue;
      }
    }
    if (char === ";") {
      statements.push(current.trim());
      current = "";
      index += 1;
      continue;
    }

    current += char;
    index += 1;
  }

  if (current.trim().length > 0) statements.push(current.trim());
  return statements.filter((statement) => statement.length > 0);
}

function skipQuoted(sql: string, start: number, quote: string): number {
  let index = start + 1;
  while (index < sql.length) {
    if (sql[index] === quote) {
      if (sql[index + 1] === quote) {
        index += 2;
        continue;
      }
      return index + 1;
    }
    index += 1;
  }
  return sql.length;
}

function dollarQuotedBody(text: string): string | null {
  const open = /(\$[A-Za-z0-9_]*\$)/u.exec(text);
  if (open === null) return null;
  const close = text.indexOf(open[1]!, open.index + open[1]!.length);
  if (close === -1) return null;
  return text.slice(open.index + open[1]!.length, close);
}

function readParenthesized(text: string, openIndex: number): string | null {
  if (text[openIndex] !== "(") return null;
  let depth = 0;
  let index = openIndex;
  while (index < text.length) {
    const char = text[index]!;
    if (char === "'") {
      index = skipQuoted(text, index, "'");
      continue;
    }
    if (char === '"') {
      index = skipQuoted(text, index, '"');
      continue;
    }
    if (char === "(") depth += 1;
    if (char === ")") {
      depth -= 1;
      if (depth === 0) return text.slice(openIndex + 1, index).trim();
    }
    index += 1;
  }
  return null;
}

function parseIdentifier(raw: string): string {
  const value = raw.trim();
  if (value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1).replaceAll('""', '"');
  }
  return value.toLowerCase();
}

function parseQualified(raw: string): { schema?: string; name: string } | undefined {
  const trimmed = raw.trim();
  const match = new RegExp(`^(${IDENTIFIER})(?:\\s*\\.\\s*(${IDENTIFIER}))?$`, "u").exec(trimmed);
  if (match === null) return undefined;
  return match[2] === undefined
    ? { name: parseIdentifier(match[1]!) }
    : { schema: parseIdentifier(match[1]!), name: parseIdentifier(match[2]!) };
}

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function parsePrivilegeNames(value: string): string[] {
  const normalized = value
    .replace(/\bprivileges\b/iu, "")
    .split(",")
    .map((entry) => entry.trim().toUpperCase())
    .filter((entry) => entry.length > 0);
  if (normalized.includes("ALL")) return [...RELATION_PRIVILEGES, "USAGE", "CREATE"];
  return normalized;
}

function isRelationPrivilege(value: string): value is RelationPrivilege {
  return (RELATION_PRIVILEGES as string[]).includes(value);
}

function attributeValue(attributes: string, name: string, fallback: boolean): boolean {
  const enabled = new RegExp(`\\b${name}\\b`, "iu").test(attributes);
  const disabled = new RegExp(`\\bno${name}\\b`, "iu").test(attributes);
  if (disabled) return false;
  if (enabled) return true;
  return fallback;
}

function relationPrivilegeKey(entry: RelationPrivilegeSnapshot): string {
  return `${entry.schema}\0${entry.table}\0${entry.grantee}\0${entry.privilege}`;
}

function defaultPrivilegeKey(entry: DefaultPrivilegeSnapshot): string {
  return `${entry.schema ?? ""}\0${entry.grantee}\0${entry.privilege}`;
}

function schemaPrivilegeKey(entry: SchemaPrivilegeSnapshot): string {
  return `${entry.schema}\0${entry.grantee}\0${entry.privilege}`;
}

function compareTables(left: TableSnapshot, right: TableSnapshot): number {
  return `${left.schema}.${left.name}`.localeCompare(`${right.schema}.${right.name}`);
}

function comparePolicies(left: PolicySnapshot, right: PolicySnapshot): number {
  return `${left.schema}.${left.table}.${left.name}`.localeCompare(`${right.schema}.${right.table}.${right.name}`);
}

function compareRelationPrivileges(left: RelationPrivilegeSnapshot, right: RelationPrivilegeSnapshot): number {
  return relationPrivilegeKey(left).localeCompare(relationPrivilegeKey(right));
}

function compareDefaultPrivileges(left: DefaultPrivilegeSnapshot, right: DefaultPrivilegeSnapshot): number {
  return defaultPrivilegeKey(left).localeCompare(defaultPrivilegeKey(right));
}

function compareSchemaPrivileges(left: SchemaPrivilegeSnapshot, right: SchemaPrivilegeSnapshot): number {
  return schemaPrivilegeKey(left).localeCompare(schemaPrivilegeKey(right));
}

function excerpt(text: string): string {
  const compact = text.replace(/\s+/gu, " ").trim();
  return compact.length <= 60 ? compact : `${compact.slice(0, 59)}…`;
}
