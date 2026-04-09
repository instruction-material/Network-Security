export interface RequestLogEntry {
  timestamp: string;
  ipAddress: string;
  method: string;
  path: string;
  status: number;
  userAgent: string;
  bodyBytes: number;
}

export interface SuspiciousSummary {
  ipAddress: string;
  reasons: string[];
}

export const sampleLogLines = [
  "2026-04-01T12:00:00Z|198.51.100.20|POST|/login|401|curl/8.5|91",
  "2026-04-01T12:00:03Z|198.51.100.20|POST|/login|401|curl/8.5|91",
  "2026-04-01T12:00:07Z|203.0.113.9|GET|/admin|404|scanner-bot|0",
];

export function parseLogLine(line: string): RequestLogEntry {
  const [timestamp, ipAddress, method, path, status, userAgent, bodyBytes] =
    line.split("|");

  return {
    timestamp,
    ipAddress,
    method,
    path,
    status: Number(status),
    userAgent,
    bodyBytes: Number(bodyBytes),
  };
}

export function summarizeSuspiciousActivity(
  logLines: string[],
): SuspiciousSummary[] {
  const entries = logLines.map(parseLogLine);

  return entries.map((entry) => ({
    ipAddress: entry.ipAddress,
    reasons: entry.status >= 400 ? ["TODO: cluster repeated failures."] : [],
  }));
}
