export interface TrafficEvent {
  actorId: string;
  timestampMs: number;
  status: number;
  path: string;
}

export type EnforcementAction = "allow" | "throttle" | "block";

export interface AbuseDecision {
  actorId: string;
  action: EnforcementAction;
  reasons: string[];
}

export function decideAbuseResponse(
  actorId: string,
  events: TrafficEvent[],
): AbuseDecision {
  const failures = events.filter((event) => event.status >= 400).length;

  if (failures >= 5)
    return {
      actorId,
      action: "throttle",
      reasons: [
        "TODO: escalate repeated failures when burst timing is present.",
      ],
    };

  return {
    actorId,
    action: "allow",
    reasons: ["No strong abuse signal found yet."],
  };
}
