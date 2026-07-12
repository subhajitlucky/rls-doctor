export function resolveConnectionString(value?: string): string {
  const connectionString = value ?? process.env.DATABASE_URL ?? process.env.SUPABASE_DB_URL;

  if (!connectionString) {
    throw new Error("Missing connection string. Pass --connection or set DATABASE_URL.");
  }

  return connectionString;
}

export function formatCliError(error: unknown, connectionString?: string): string {
  let message = error instanceof Error ? error.message : String(error);
  const secrets = connectionString ? connectionSecrets(connectionString) : [];

  message = message.replace(/\b(postgres(?:ql)?:\/\/)[^\s/@]+@/gi, "$1[redacted]@");

  for (const secret of secrets.sort((left, right) => right.length - left.length)) {
    message = message.split(secret).join("[redacted]");
  }

  return message;
}

function connectionSecrets(connectionString: string): string[] {
  const secrets = new Set<string>([connectionString]);

  try {
    const url = new URL(connectionString);
    const encodedUserInfo = [url.username, url.password].filter(Boolean).join(":");
    const decodedUsername = safeDecode(url.username);
    const decodedPassword = safeDecode(url.password);
    const decodedUserInfo = [decodedUsername, decodedPassword].filter(Boolean).join(":");

    for (const value of [
      encodedUserInfo,
      decodedUserInfo,
      url.username,
      url.password,
      decodedUsername,
      decodedPassword,
      encodeURIComponent(decodedUsername),
      encodeURIComponent(decodedPassword)
    ]) {
      if (value) secrets.add(value);
    }
  } catch {
    // Generic Postgres URL user-info redaction still protects malformed URLs in messages.
  }

  return [...secrets];
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
