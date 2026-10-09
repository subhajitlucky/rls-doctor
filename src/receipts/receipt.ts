import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { reportFindingFingerprints } from "../audit/fingerprint.js";
import type { AuditReport, Severity } from "../audit/types.js";

export const RECEIPT_VERSION = "1";

export interface ReceiptCoverage {
  complete: boolean;
  limitations: string[];
}

export interface ReceiptSignature {
  algorithm: "ed25519";
  publicKey: string;
  value: string;
}

export interface CoverageReceipt {
  receiptVersion: string;
  tool: { name: string; version: string };
  issuedAt: string;
  subject: { root: string; scope: string };
  score: { value: number; band: string };
  coverage: ReceiptCoverage;
  findings: {
    total: number;
    bySeverity: Record<Severity, number>;
    fingerprints: string[];
  };
  suppressed: number;
  shadow?: boolean;
  digest: { algorithm: "sha256"; value: string };
  signature?: ReceiptSignature;
}

type ReceiptBody = Omit<CoverageReceipt, "digest" | "signature">;

/**
 * Deterministic JSON with recursively sorted object keys. The digest is
 * computed over the canonical body, so any change to a single character of
 * the receipt body invalidates verification.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entry]) => entry !== undefined)
    .sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`).join(",")}}`;
}

export function receiptDigest(body: ReceiptBody): string {
  return createHash("sha256").update(canonicalJson(body), "utf8").digest("hex");
}

export interface BuildReceiptOptions {
  issuedAt?: Date;
  privateKeyPem?: string;
  source: "catalog" | "schema-file" | "shadow";
  toolVersion: string;
  shadow?: boolean;
  additionalLimitations?: readonly string[];
}

/**
 * Build a coverage receipt from an RLS audit report: what was checked, what
 * was not, the deterministic score, and finding fingerprints. Signing is
 * optional and proves the holder of the private key issued the receipt.
 */
export function buildReceipt(report: AuditReport, options: BuildReceiptOptions): CoverageReceipt {
  const limitations = [...(report.limitations ?? []), ...(options.additionalLimitations ?? [])];
  const bySeverity = { ...report.summary.findings };
  const body: ReceiptBody = {
    receiptVersion: RECEIPT_VERSION,
    tool: { name: "rls-doctor", version: options.toolVersion },
    issuedAt: (options.issuedAt ?? new Date()).toISOString(),
    subject: { root: report.schemas.join(", "), scope: options.source },
    score: { value: report.score.value, band: report.score.band },
    coverage: { complete: limitations.length === 0, limitations },
    findings: {
      total: Object.values(bySeverity).reduce((sum, count) => sum + count, 0),
      bySeverity,
      fingerprints: reportFindingFingerprints(report),
    },
    suppressed: 0,
    ...(options.shadow === true ? { shadow: true } : {}),
  };

  const receipt: CoverageReceipt = {
    ...body,
    digest: { algorithm: "sha256", value: receiptDigest(body) },
  };

  if (options.privateKeyPem !== undefined) {
    const privateKey = createPrivateKey(options.privateKeyPem);
    const publicKey = createPublicKey(privateKey);
    receipt.signature = {
      algorithm: "ed25519",
      publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
      value: sign(null, Buffer.from(canonicalJson(body), "utf8"), privateKey).toString("base64"),
    };
  }

  return receipt;
}

export function serializeReceipt(receipt: CoverageReceipt): string {
  return `${JSON.stringify(receipt, null, 2)}\n`;
}

export interface ReceiptVerification {
  valid: boolean;
  reasons: string[];
  summary: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function verifyReceipt(value: unknown): ReceiptVerification {
  const reasons: string[] = [];
  if (!isRecord(value)) {
    return { valid: false, reasons: ["receipt is not a JSON object"], summary: "" };
  }

  if (value.receiptVersion !== RECEIPT_VERSION) {
    reasons.push(`unsupported receiptVersion: ${String(value.receiptVersion)}`);
  }
  const { digest, signature, ...body } = value as Partial<CoverageReceipt>;
  if (!isRecord(digest) || digest.algorithm !== "sha256" || typeof digest.value !== "string") {
    reasons.push("missing or invalid digest");
  } else if (receiptDigest(body as ReceiptBody) !== digest.value) {
    reasons.push("digest mismatch: the receipt body was modified after issuance");
  }

  if (signature !== undefined) {
    if (
      !isRecord(signature) ||
      signature.algorithm !== "ed25519" ||
      typeof signature.value !== "string" ||
      typeof signature.publicKey !== "string"
    ) {
      reasons.push("invalid signature block");
    } else if (reasons.length === 0) {
      try {
        const valid = verify(
          null,
          Buffer.from(canonicalJson(body), "utf8"),
          createPublicKey(signature.publicKey),
          Buffer.from(signature.value, "base64"),
        );
        if (!valid) reasons.push("signature does not match the receipt body");
      } catch {
        reasons.push("signature could not be verified");
      }
    }
  }

  return {
    valid: reasons.length === 0,
    reasons,
    summary: reasons.length === 0 ? receiptSummary(value as unknown as CoverageReceipt) : "",
  };
}

function receiptSummary(receipt: CoverageReceipt): string {
  const lines = [
    `receipt: ${receipt.tool.name} ${receipt.tool.version} · issued ${receipt.issuedAt}`,
    `subject: ${receipt.subject.root} (scope=${receipt.subject.scope})`,
    ...(receipt.shadow === true ? ["environment: shadow (disposable world)"] : []),
    `score: ${receipt.score.value}/100 (${receipt.score.band})`,
    `coverage: ${receipt.coverage.complete ? "complete" : "incomplete"}`,
  ];
  for (const limitation of receipt.coverage.limitations) {
    lines.push(`  - ${limitation}`);
  }
  const counts = Object.entries(receipt.findings.bySeverity)
    .filter(([, count]) => count > 0)
    .map(([severity, count]) => `${severity} ${count}`)
    .join(", ");
  lines.push(`findings: ${receipt.findings.total}${counts.length === 0 ? "" : ` (${counts})`}`);
  lines.push(`signature: ${receipt.signature === undefined ? "none (digest only)" : "ed25519"}`);
  lines.push("integrity: digest verified");
  return `${lines.join("\n")}\n`;
}
