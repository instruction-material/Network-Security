// Store security-relevant state for one real-time connection
export interface ConnectionContext {
    connectionId: string;
    userId: string | null;
    roomIds: string[];
    invalidEventCount: number;
}

// Store one real-time event submitted by a client
export interface RealtimeEvent {
    type: string;
    roomId: string;
    payloadSize: number;
}

// Store the accept or reject decision for an event
export interface EventDecision {
    accepted: boolean;
    disconnect: boolean;
    reason: string;
}

const MAX_EVENT_SIZE = 2_048;
const DISCONNECT_INVALID_EVENT_THRESHOLD = 2;
const ALLOWED_EVENT_TYPES = new Set<string>([
    "subscribe",
    "unsubscribe",
    "notify",
]);

/**
 * @brief Evaluate whether a real-time event should be accepted
 *
 * @param context Connection context for the sending client
 *
 * @param event Event submitted by the client
 *
 * @return Event decision with accept and disconnect flags
 */
export function evaluateRealtimeEvent(
    context: ConnectionContext,
    event: RealtimeEvent,
): EventDecision {
    // Disconnect unauthenticated connections that attempt to send events
    if (context.userId === null) {
        return {
            accepted: false,
            disconnect: true,
            reason: "Unauthenticated connections cannot send events.",
        };
    }

    // Reject unknown event types and disconnect after repeated invalid events
    if (!ALLOWED_EVENT_TYPES.has(event.type)) {
        return {
            accepted: false,
            disconnect:
                context.invalidEventCount >= DISCONNECT_INVALID_EVENT_THRESHOLD,
            reason: "Unknown event type.",
        };
    }

    // Reject room events outside the connection's authorized rooms
    if (!context.roomIds.includes(event.roomId) && event.type !== "subscribe") {
        return {
            accepted: false,
            disconnect: false,
            reason: "The connection is not authorized for that room.",
        };
    }

    // Reject oversized events and disconnect after repeated invalid events
    if (event.payloadSize > MAX_EVENT_SIZE) {
        return {
            accepted: false,
            disconnect:
                context.invalidEventCount >= DISCONNECT_INVALID_EVENT_THRESHOLD,
            reason: "Event payload exceeds the allowed size.",
        };
    }

    // Accept events that pass authentication, type, room, and size checks
    return {
        accepted: true,
        disconnect: false,
        reason: "Event accepted.",
    };
}
