export type Protocol = "tcp" | "udp";
export type BindScope = "loopback" | "lan" | "public" | "unknown";
export type ExposureRisk = "low" | "medium" | "high";

export interface ListenerRecord {
  protocol: Protocol;
  address: string;
  port: number;
  processName: string;
  bindScope: BindScope;
  expectsAuthentication: boolean;
}

export interface ExposureAssessment {
  risk: ExposureRisk;
  reason: string;
}

export interface InventorySummary {
  totalListeners: number;
  highRiskListeners: ListenerRecord[];
  reportLines: string[];
}

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

function isManagementPort(port: number) {
  return port === 22 || port === 3389;
}

export function assessListenerExposure(
  listener: ListenerRecord,
): ExposureAssessment {
  if (listener.bindScope === "loopback")
    return {
      risk: "low",
      reason: "Loopback listeners stay on the host boundary.",
    };

  if (listener.bindScope === "public" && !listener.expectsAuthentication)
    return {
      risk: "high",
      reason:
        "Public unauthenticated listeners should be justified and tightly controlled.",
    };

  if (listener.bindScope === "public" && isManagementPort(listener.port))
    return {
      risk: "high",
      reason:
        "Public management ports need explicit review, rate limits, and log visibility.",
    };

  if (listener.bindScope === "lan")
    return {
      risk: "medium",
      reason:
        "LAN-visible services still widen the attack surface and should remain intentional.",
    };

  return {
    risk: "medium",
    reason:
      "Unknown or partially authenticated listeners deserve manual verification.",
  };
}

export function buildInventorySummary(
  listeners: ListenerRecord[],
): InventorySummary {
  const reportLines = listeners.map((listener) => {
    const assessment = assessListenerExposure(listener);
    return `${listener.processName}:${listener.port} -> ${assessment.risk} (${assessment.reason})`;
  });

  return {
    totalListeners: listeners.length,
    highRiskListeners: listeners.filter(
      (listener) => assessListenerExposure(listener).risk === "high",
    ),
    reportLines,
  };
}
