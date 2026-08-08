// Store the proxy settings that affect transport and exposure risk
export interface ProxyConfig {
    tlsEnabled: boolean;
    redirectsHttpToHttps: boolean;
    trustsForwardedHeaders: boolean;
    publicAppPort: number;
    internalAppPort: number;
    adminRoutePublic: boolean;
}

// Store one audit finding for the proxy configuration
export interface AuditFinding {
    severity: "low" | "medium" | "high";
    message: string;
}

/**
 * @brief Audit a proxy configuration for common boundary risks
 *
 * @param config Proxy configuration to audit
 *
 * @return Findings describing transport and exposure risks
 */
export function auditProxyConfig(config: ProxyConfig): AuditFinding[] {
    const findings: AuditFinding[] = [];

    // Require TLS at the public edge
    if (!config.tlsEnabled) {
        findings.push({
            severity: "high",
            message: "TLS is disabled on the public edge.",
        });
    }

    // Require public HTTP to redirect to HTTPS
    if (!config.redirectsHttpToHttps) {
        findings.push({
            severity: "medium",
            message:
                "Public HTTP should redirect cleanly to HTTPS to avoid mixed transport and weak entry paths.",
        });
    }

    // Require explicit handling for forwarded proxy headers
    if (!config.trustsForwardedHeaders) {
        findings.push({
            severity: "medium",
            message:
                "Forwarded headers are not being handled explicitly, which can corrupt scheme or client-IP reasoning.",
        });
    }

    // Keep public and internal ports separated in the model
    if (config.publicAppPort === config.internalAppPort) {
        findings.push({
            severity: "medium",
            message:
                "The same port is being treated as both public and internal, which weakens exposure separation.",
        });
    }

    // Flag public admin routes as high-risk exposure
    if (config.adminRoutePublic) {
        findings.push({
            severity: "high",
            message: "Admin routes should not be publicly exposed by default.",
        });
    }

    // Add a clean result when no configured risk checks failed
    if (findings.length === 0) {
        findings.push({
            severity: "low",
            message:
                "No obvious transport or proxy boundary issues were detected in this configuration.",
        });
    }

    return findings;
}
