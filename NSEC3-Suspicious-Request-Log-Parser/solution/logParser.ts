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
  const grouped = new Map<string, RequestLogEntry[]>();

  for (const entry of logLines.map(parseLogLine)) {
    const existing = grouped.get(entry.ipAddress) ?? [];
    existing.push(entry);
    grouped.set(entry.ipAddress, existing);
  }

  return [...grouped.entries()].map(([ipAddress, entries]) => {
    const reasons: string[] = [];
    const failedRequests = entries.filter((entry) => entry.status >= 400);
    const targetedAdminPaths = entries.some((entry) =>
      entry.path.startsWith("/admin"),
    );
    const scriptedUserAgent = entries.some(
      (entry) =>
        entry.userAgent.toLowerCase().includes("bot") ||
        entry.userAgent.toLowerCase().includes("curl"),
    );

    if (failedRequests.length >= 2)
      reasons.push("Repeated failing requests from the same address.");
    if (targetedAdminPaths) reasons.push("Touched an admin-style path.");
    if (scriptedUserAgent)
      reasons.push("User agent looks automated or scripted.");

    return {
      ipAddress,
      reasons,
    };
  });
}
