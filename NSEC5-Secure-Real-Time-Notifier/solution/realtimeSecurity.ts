export interface ConnectionContext {
  connectionId: string;
  userId: string | null;
  roomIds: string[];
  invalidEventCount: number;
}

export interface RealtimeEvent {
  type: string;
  roomId: string;
  payloadSize: number;
}

export interface EventDecision {
  accepted: boolean;
  disconnect: boolean;
  reason: string;
}

const MAX_EVENT_SIZE = 2_048;
const ALLOWED_EVENT_TYPES = new Set(["subscribe", "unsubscribe", "notify"]);

export function evaluateRealtimeEvent(
  context: ConnectionContext,
  event: RealtimeEvent,
): EventDecision {
  if (context.userId === null)
    return {
      accepted: false,
      disconnect: true,
      reason: "Unauthenticated connections cannot send events.",
    };

  if (!ALLOWED_EVENT_TYPES.has(event.type))
    return {
      accepted: false,
      disconnect: context.invalidEventCount >= 2,
      reason: "Unknown event type.",
    };

  if (!context.roomIds.includes(event.roomId) && event.type !== "subscribe")
    return {
      accepted: false,
      disconnect: false,
      reason: "The connection is not authorized for that room.",
    };

  if (event.payloadSize > MAX_EVENT_SIZE)
    return {
      accepted: false,
      disconnect: context.invalidEventCount >= 2,
      reason: "Event payload exceeds the allowed size.",
    };

  return {
    accepted: true,
    disconnect: false,
    reason: "Event accepted.",
  };
}
