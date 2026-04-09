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
const REQUIRED_FIELDS = ["channelId", "message"];

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
        message: "TODO: require a more specific schema rule.",
      });
  }

  return errors;
}

export function buildBoundaryDecision(
  request: BoundaryRequest,
): BoundaryDecision {
  const errors = validateBoundaryRequest(request);

  return {
    accepted: errors.length === 0 && request.authenticatedUserId !== null,
    errors,
  };
}
