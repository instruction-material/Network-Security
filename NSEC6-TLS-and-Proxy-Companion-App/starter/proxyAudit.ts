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
      message: "TODO: explain the downgrade and mixed-transport risk.",
    });

  if (config.adminRoutePublic)
    findings.push({
      severity: "high",
      message: "Admin routes should not be publicly exposed by default.",
    });

  return findings;
}
