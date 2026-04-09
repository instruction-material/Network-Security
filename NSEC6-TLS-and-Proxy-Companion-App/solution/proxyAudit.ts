export interface ProxyConfig {
  tlsEnabled: boolean;
  redirectsHttpToHttps: boolean;
  trustsForwardedHeaders: boolean;
  publicAppPort: number;
  internalAppPort: number;
  adminRoutePublic: boolean;
}

export interface AuditFinding {
  severity: "low" | "medium" | "high";
  message: string;
}

export function auditProxyConfig(config: ProxyConfig): AuditFinding[] {
  const findings: AuditFinding[] = [];

  if (!config.tlsEnabled)
    findings.push({
      severity: "high",
      message: "TLS is disabled on the public edge.",
    });

  if (!config.redirectsHttpToHttps)
    findings.push({
      severity: "medium",
      message:
        "Public HTTP should redirect cleanly to HTTPS to avoid mixed transport and weak entry paths.",
    });

  if (!config.trustsForwardedHeaders)
    findings.push({
      severity: "medium",
      message:
        "Forwarded headers are not being handled explicitly, which can corrupt scheme or client-IP reasoning.",
    });

  if (config.publicAppPort === config.internalAppPort)
    findings.push({
      severity: "medium",
      message:
        "The same port is being treated as both public and internal, which weakens exposure separation.",
    });

  if (config.adminRoutePublic)
    findings.push({
      severity: "high",
      message: "Admin routes should not be publicly exposed by default.",
    });

  if (findings.length === 0)
    findings.push({
      severity: "low",
      message:
        "No obvious transport or proxy boundary issues were detected in this configuration.",
    });

  return findings;
}
