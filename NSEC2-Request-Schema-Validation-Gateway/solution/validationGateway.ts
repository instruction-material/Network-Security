export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface BoundaryRequest {
  method: HttpMethod;
  path: string;
  bodySize: number;
  authenticatedUserId: string | null;
  payload: Record<string, unknown>;
}

export interface ValidationError {
  field: string;
  message: string;
}

export interface BoundaryDecision {
  accepted: boolean;
  errors: ValidationError[];
}

const MAX_BODY_SIZE = 8_192;
const MAX_MESSAGE_LENGTH = 280;
const REQUIRED_FIELDS = ["channelId", "message"] as const;

function isNonEmptyString(value: unknown) {
  return typeof value === "string" && value.trim().length > 0;
}

export function validateBoundaryRequest(
  request: BoundaryRequest,
): ValidationError[] {
  const errors: ValidationError[] = [];

  if (request.method !== "POST")
    errors.push({
      field: "method",
      message: "Only POST is allowed for this boundary.",
    });

  if (request.bodySize > MAX_BODY_SIZE)
    errors.push({
      field: "bodySize",
      message: "Request body exceeds the current limit.",
    });

  for (const field of REQUIRED_FIELDS) {
    if (!(field in request.payload))
      errors.push({
        field,
        message: "Required field is missing.",
      });
  }

  if (
    "channelId" in request.payload &&
    !isNonEmptyString(request.payload.channelId)
  )
    errors.push({
      field: "channelId",
      message: "channelId must be a non-empty string.",
    });

  if ("message" in request.payload) {
    if (!isNonEmptyString(request.payload.message))
      errors.push({
        field: "message",
        message: "message must be a non-empty string.",
      });
    else if ((request.payload.message as string).length > MAX_MESSAGE_LENGTH)
      errors.push({
        field: "message",
        message: "message exceeds the allowed length.",
      });
  }

  return errors;
}

export function buildBoundaryDecision(
  request: BoundaryRequest,
): BoundaryDecision {
  const errors = validateBoundaryRequest(request);

  if (request.authenticatedUserId === null)
    errors.push({
      field: "authenticatedUserId",
      message: "An authenticated user is required.",
    });

  return {
    accepted: errors.length === 0,
    errors,
  };
}
