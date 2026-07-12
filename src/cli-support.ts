export function resolveConnectionString(value?: string): string {
  const connectionString = [value, process.env.DATABASE_URL, process.env.SUPABASE_DB_URL].find(
    (candidate): candidate is string => typeof candidate === "string" && candidate.trim().length > 0
  );

  if (!connectionString) {
    throw new Error("Missing connection string. Pass --connection or set DATABASE_URL.");
  }

  return connectionString;
}

export function formatCliError(error: unknown, connectionString?: string): string {
  let message = error instanceof Error ? error.message : String(error);

  // Redact every Postgres URL's user-info while retaining its host, port, and path.
  message = message.replace(/\b(postgres(?:ql)?:\/\/)[^\s/@]+@/gi, "$1[redacted]@");

  if (!connectionString) return message;

  const credentials = parseCredentials(connectionString);

  // A malformed connection string may not match the generic URL pattern above.
  if (message.includes(connectionString)) {
    message = message.split(connectionString).join("[redacted connection]");
  }

  for (const credential of credentials.components) {
    message = redactLabeledCredential(message, credential);
  }

  for (const userInfo of credentials.userInfo) {
    message = redactAuthenticationUserInfo(message, userInfo);
  }

  return message;
}

interface Credentials {
  components: string[];
  userInfo: string[];
}

function parseCredentials(connectionString: string): Credentials {
  const components = new Set<string>();
  const userInfo = new Set<string>();

  try {
    const url = new URL(connectionString);
    const decodedUsername = safeDecode(url.username);
    const decodedPassword = safeDecode(url.password);

    addNonEmpty(components, url.username, url.password, decodedUsername, decodedPassword);
    addNonEmpty(
      components,
      encodeURIComponent(decodedUsername),
      encodeURIComponent(decodedPassword)
    );
    addNonEmpty(
      userInfo,
      joinUserInfo(url.username, url.password),
      joinUserInfo(decodedUsername, decodedPassword),
      joinUserInfo(encodeURIComponent(decodedUsername), encodeURIComponent(decodedPassword))
    );
  } catch {
    // URL user-info redaction above and exact-string redaction remain available.
  }

  return { components: [...components], userInfo: [...userInfo] };
}

function redactLabeledCredential(message: string, credential: string): string {
  const escaped = escapeRegExp(credential);
  const pattern = new RegExp(
    `(\\b(?:user|username|password)\\b\\s*(?:=|:|\\s)\\s*["']?)${escaped}(?=["']?(?:\\s|[;,.)]|$))`,
    "gi"
  );
  return message.replace(pattern, "$1[redacted]");
}

function redactAuthenticationUserInfo(message: string, userInfo: string): string {
  const escaped = escapeRegExp(userInfo);
  const direct = new RegExp(
    `(\\bauthentication\\s+failed\\s+for\\s+["']?)${escaped}(?=["']?(?:\\s|[;,.)]|$))`,
    "gi"
  );
  let redacted = message.replace(direct, "$1[redacted]");

  if (/\bauthentication\b/i.test(redacted)) {
    const parenthesized = new RegExp(`(\\()${escaped}(?=\\))`, "g");
    redacted = redacted.replace(parenthesized, "$1[redacted]");
  }

  return redacted;
}

function joinUserInfo(username: string, password: string): string {
  return username && password ? `${username}:${password}` : username || password;
}

function addNonEmpty(target: Set<string>, ...values: string[]): void {
  for (const value of values) {
    if (value) target.add(value);
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
