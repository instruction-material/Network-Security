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

function countBursts(events: TrafficEvent[]) {
  let burstCount = 0;

  for (let index = 1; index < events.length; index += 1) {
    if (events[index].timestampMs - events[index - 1].timestampMs <= 1_000)
      burstCount += 1;
  }

  return burstCount;
}

export function decideAbuseResponse(
  actorId: string,
  events: TrafficEvent[],
): AbuseDecision {
  const orderedEvents = [...events].sort(
    (left, right) => left.timestampMs - right.timestampMs,
  );
  const failures = orderedEvents.filter((event) => event.status >= 400).length;
  const adminTargeting = orderedEvents.some((event) =>
    event.path.startsWith("/admin"),
  );
  const bursts = countBursts(orderedEvents);

  if (failures >= 6 || (adminTargeting && bursts >= 3))
    return {
      actorId,
      action: "block",
      reasons: [
        "Repeated failures or burst targeting reached the block threshold.",
      ],
    };

  if (failures >= 3 || bursts >= 2)
    return {
      actorId,
      action: "throttle",
      reasons: [
        "Traffic is bursty or failure-heavy and should be slowed down.",
      ],
    };

  return {
    actorId,
    action: "allow",
    reasons: ["No strong abuse signal found yet."],
  };
}
