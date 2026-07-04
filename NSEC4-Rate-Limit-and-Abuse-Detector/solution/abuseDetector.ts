// Store one request or traffic event for an actor
export interface TrafficEvent {
  actorId: string;
  timestampMs: number;
  status: number;
  path: string;
}

// Define enforcement actions used by the abuse detector
export type EnforcementAction = "allow" | "throttle" | "block";

// Store the action and reasons selected for an actor
export interface AbuseDecision {
  actorId: string;
  action: EnforcementAction;
  reasons: string[];
}

const BURST_WINDOW_MS = 1_000;
const BLOCK_FAILURE_THRESHOLD = 6;
const BLOCK_BURST_THRESHOLD = 3;
const THROTTLE_FAILURE_THRESHOLD = 3;
const THROTTLE_BURST_THRESHOLD = 2;
const CLIENT_ERROR_STATUS = 400;

// Count adjacent events that occur inside the burst window
function countBursts(events: TrafficEvent[]): number {
  let burstCount = 0;

  // Compare each event with the prior event in timestamp order
  for (let index = 1; index < events.length; index += 1) {
    // Count traffic bursts that fit inside the configured window
    if (
      events[index].timestampMs - events[index - 1].timestampMs <=
      BURST_WINDOW_MS
    ) {
      burstCount += 1;
    }
  }

  return burstCount;
}

/**
 * @brief Decide how to respond to an actor's traffic
 *
 * @param actorId Actor being evaluated
 *
 * @param events Traffic events associated with the actor
 *
 * @return Enforcement decision with supporting reasons
 */
export function decideAbuseResponse(
  actorId: string,
  events: TrafficEvent[],
): AbuseDecision {
  // Sort events before checking for timing-based bursts
  const orderedEvents = [...events].sort(
    (left, right) => left.timestampMs - right.timestampMs,
  );
  const failures = orderedEvents.filter(
    (event) => event.status >= CLIENT_ERROR_STATUS,
  ).length;
  const adminTargeting = orderedEvents.some((event) =>
    event.path.startsWith("/admin"),
  );
  const bursts = countBursts(orderedEvents);

  // Block repeated failures or burst targeting against admin routes
  if (
    failures >= BLOCK_FAILURE_THRESHOLD ||
    (adminTargeting && bursts >= BLOCK_BURST_THRESHOLD)
  ) {
    return {
      actorId,
      action: "block",
      reasons: [
        "Repeated failures or burst targeting reached the block threshold.",
      ],
    };
  }

  // Throttle suspicious traffic that has not crossed the block threshold
  if (
    failures >= THROTTLE_FAILURE_THRESHOLD ||
    bursts >= THROTTLE_BURST_THRESHOLD
  ) {
    return {
      actorId,
      action: "throttle",
      reasons: [
        "Traffic is bursty or failure-heavy and should be slowed down.",
      ],
    };
  }

  // Allow traffic when no strong abuse signal is present
  return {
    actorId,
    action: "allow",
    reasons: ["No strong abuse signal found yet."],
  };
}
