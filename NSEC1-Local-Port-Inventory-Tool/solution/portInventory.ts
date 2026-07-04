// Define the network protocols students classify in the inventory
export type Protocol = "tcp" | "udp";

// Define where a listener is bound from an exposure perspective
export type BindScope = "loopback" | "lan" | "public" | "unknown";

// Define the risk labels reported by the assessment
export type ExposureRisk = "low" | "medium" | "high";

// Store one listening service discovered during inventory
export interface ListenerRecord {
  protocol: Protocol;
  address: string;
  port: number;
  processName: string;
  bindScope: BindScope;
  expectsAuthentication: boolean;
}

// Store the assessment result for one listener
export interface ExposureAssessment {
  risk: ExposureRisk;
  reason: string;
}

// Store the full report shown to the learner
export interface InventorySummary {
  totalListeners: number;
  highRiskListeners: ListenerRecord[];
  reportLines: string[];
}

const MANAGEMENT_PORTS = new Set([22, 3389]);

// Provide representative listeners for the lesson walkthrough
export const sampleListeners: ListenerRecord[] = [
  {
    protocol: "tcp",
    address: "127.0.0.1",
    port: 3000,
    processName: "dev-api",
    bindScope: "loopback",
    expectsAuthentication: true,
  },
  {
    protocol: "tcp",
    address: "0.0.0.0",
    port: 22,
    processName: "sshd",
    bindScope: "public",
    expectsAuthentication: true,
  },
  {
    protocol: "udp",
    address: "0.0.0.0",
    port: 5353,
    processName: "multicast-helper",
    bindScope: "lan",
    expectsAuthentication: false,
  },
];

// Check whether a port is commonly used for remote management
function isManagementPort(port: number): boolean {
  return MANAGEMENT_PORTS.has(port);
}

/**
 * @brief Assess the exposure risk for one listener
 *
 * @param listener Listener record to evaluate
 *
 * @return Exposure assessment with a risk label and explanation
 */
export function assessListenerExposure(
  listener: ListenerRecord,
): ExposureAssessment {
  // Treat loopback listeners as local-only exposure
  if (listener.bindScope === "loopback") {
    return {
      risk: "low",
      reason: "Loopback listeners stay on the host boundary.",
    };
  }

  // Flag public unauthenticated services as high risk
  if (listener.bindScope === "public" && !listener.expectsAuthentication) {
    return {
      risk: "high",
      reason:
        "Public unauthenticated listeners should be justified and tightly controlled.",
    };
  }

  // Flag public management ports for explicit review
  if (listener.bindScope === "public" && isManagementPort(listener.port)) {
    return {
      risk: "high",
      reason:
        "Public management ports need explicit review, rate limits, and log visibility.",
    };
  }

  // Treat LAN-visible services as medium risk because they cross the host boundary
  if (listener.bindScope === "lan") {
    return {
      risk: "medium",
      reason:
        "LAN-visible services still widen the attack surface and should remain intentional.",
    };
  }

  return {
    risk: "medium",
    reason:
      "Unknown or partially authenticated listeners deserve manual verification.",
  };
}

/**
 * @brief Build a compact inventory report from listener records
 *
 * @param listeners Listener records to summarize
 *
 * @return Inventory summary with counts, high-risk records, and report lines
 */
export function buildInventorySummary(
  listeners: ListenerRecord[],
): InventorySummary {
  // Build a readable report line for each listener
  const reportLines = listeners.map((listener) => {
    const assessment = assessListenerExposure(listener);
    return `${listener.processName}:${listener.port} -> ${assessment.risk} (${assessment.reason})`;
  });

  // Return the full summary object used by the lesson
  return {
    totalListeners: listeners.length,
    highRiskListeners: listeners.filter(
      (listener) => assessListenerExposure(listener).risk === "high",
    ),
    reportLines,
  };
}
