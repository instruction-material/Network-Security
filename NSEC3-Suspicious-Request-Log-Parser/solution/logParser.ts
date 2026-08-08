// Store one parsed request log entry
export interface RequestLogEntry {
    timestamp: string;
    ipAddress: string;
    method: string;
    path: string;
    status: number;
    userAgent: string;
    bodyBytes: number;
}

// Store suspicious activity reasons for one source address
export interface SuspiciousSummary {
    ipAddress: string;
    reasons: string[];
}

const LOG_TIMESTAMP_INDEX = 0;
const LOG_IP_ADDRESS_INDEX = 1;
const LOG_METHOD_INDEX = 2;
const LOG_PATH_INDEX = 3;
const LOG_STATUS_INDEX = 4;
const LOG_USER_AGENT_INDEX = 5;
const LOG_BODY_BYTES_INDEX = 6;
const CLIENT_ERROR_STATUS = 400;
const REPEATED_FAILURE_THRESHOLD = 2;

// Provide representative log lines for the lesson walkthrough
export const sampleLogLines = [
    "2026-04-01T12:00:00Z|198.51.100.20|POST|/login|401|curl/8.5|91",
    "2026-04-01T12:00:03Z|198.51.100.20|POST|/login|401|curl/8.5|91",
    "2026-04-01T12:00:07Z|203.0.113.9|GET|/admin|404|scanner-bot|0",
];

/**
 * @brief Parse one pipe-delimited request log line
 *
 * @param line Log line to parse
 *
 * @return Parsed request log entry
 */
export function parseLogLine(line: string): RequestLogEntry {
    const fields = line.split("|");

    // Map fixed log columns into a named request object
    return {
        timestamp: fields[LOG_TIMESTAMP_INDEX],
        ipAddress: fields[LOG_IP_ADDRESS_INDEX],
        method: fields[LOG_METHOD_INDEX],
        path: fields[LOG_PATH_INDEX],
        status: Number(fields[LOG_STATUS_INDEX]),
        userAgent: fields[LOG_USER_AGENT_INDEX],
        bodyBytes: Number(fields[LOG_BODY_BYTES_INDEX]),
    };
}

/**
 * @brief Summarize suspicious activity grouped by source address
 *
 * @param logLines Raw log lines to analyze
 *
 * @return Suspicious summary for each source address
 */
export function summarizeSuspiciousActivity(
    logLines: string[],
): SuspiciousSummary[] {
    const grouped = new Map<string, RequestLogEntry[]>();

    // Group parsed entries by IP address
    for (const entry of logLines.map(parseLogLine)) {
        const existing = grouped.get(entry.ipAddress) ?? [];
        existing.push(entry);
        grouped.set(entry.ipAddress, existing);
    }

    // Build one summary per source address
    return [...grouped.entries()].map(([ipAddress, entries]) => {
        const reasons: string[] = [];
        const failedRequests = entries.filter(
            (entry) => entry.status >= CLIENT_ERROR_STATUS,
        );
        const targetedAdminPaths = entries.some((entry) =>
            entry.path.startsWith("/admin"),
        );
        const scriptedUserAgent = entries.some(
            (entry) =>
                entry.userAgent.toLowerCase().includes("bot") ||
                entry.userAgent.toLowerCase().includes("curl"),
        );

        // Flag repeated client or server failures from the same address
        if (failedRequests.length >= REPEATED_FAILURE_THRESHOLD) {
            reasons.push("Repeated failing requests from the same address.");
        }

        // Flag requests that probe protected admin-style routes
        if (targetedAdminPaths) {
            reasons.push("Touched an admin-style path.");
        }

        // Flag user agents that look scripted rather than browser-driven
        if (scriptedUserAgent) {
            reasons.push("User agent looks automated or scripted.");
        }

        return {
            ipAddress,
            reasons,
        };
    });
}
