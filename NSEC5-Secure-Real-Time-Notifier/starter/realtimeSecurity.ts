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

  if (event.payloadSize > MAX_EVENT_SIZE)
    return {
      accepted: false,
      disconnect: false,
      reason: "TODO: apply a stricter repeated-abuse policy.",
    };

  return {
    accepted: true,
    disconnect: false,
    reason: "Event accepted.",
  };
}
