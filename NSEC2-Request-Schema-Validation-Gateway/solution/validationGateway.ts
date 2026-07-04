// Define the HTTP methods accepted by the boundary model
export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

// Store one inbound request at the application boundary
export interface BoundaryRequest {
  method: HttpMethod;
  path: string;
  bodySize: number;
  authenticatedUserId: string | null;
  payload: Record<string, unknown>;
}

// Store one validation error for a request field
export interface ValidationError {
  field: string;
  message: string;
}

// Store the final allow or reject decision for the boundary
export interface BoundaryDecision {
  accepted: boolean;
  errors: ValidationError[];
}

const MAX_BODY_SIZE = 8_192;
const MAX_MESSAGE_LENGTH = 280;
const REQUIRED_FIELDS = ["channelId", "message"] as const;

// Check whether an unknown value is a non-empty string after trimming
function isNonEmptyString(value: unknown): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

/**
 * @brief Validate one request at the API boundary
 *
 * @param request Request to validate
 *
 * @return Validation errors found in the request
 */
export function validateBoundaryRequest(
  request: BoundaryRequest,
): ValidationError[] {
  const errors: ValidationError[] = [];

  // Reject methods outside the accepted boundary contract
  if (request.method !== "POST") {
    errors.push({
      field: "method",
      message: "Only POST is allowed for this boundary.",
    });
  }

  // Reject bodies larger than the configured limit
  if (request.bodySize > MAX_BODY_SIZE) {
    errors.push({
      field: "bodySize",
      message: "Request body exceeds the current limit.",
    });
  }

  // Require each field needed by the downstream handler
  for (const field of REQUIRED_FIELDS) {
    // Report missing payload fields individually
    if (!(field in request.payload)) {
      errors.push({
        field,
        message: "Required field is missing.",
      });
    }
  }

  // Validate channel id only when the field is present
  if (
    "channelId" in request.payload &&
    !isNonEmptyString(request.payload.channelId)
  ) {
    errors.push({
      field: "channelId",
      message: "channelId must be a non-empty string.",
    });
  }

  // Validate message type and length only when the field is present
  if ("message" in request.payload) {
    // Reject empty or non-string messages
    if (!isNonEmptyString(request.payload.message)) {
      errors.push({
        field: "message",
        message: "message must be a non-empty string.",
      });
    }
    // Reject messages that exceed the configured length
    else if ((request.payload.message as string).length > MAX_MESSAGE_LENGTH) {
      errors.push({
        field: "message",
        message: "message exceeds the allowed length.",
      });
    }
  }

  return errors;
}

/**
 * @brief Build the final boundary decision for a request
 *
 * @param request Request to validate and authorize
 *
 * @return Boundary decision with all validation errors
 */
export function buildBoundaryDecision(
  request: BoundaryRequest,
): BoundaryDecision {
  const errors = validateBoundaryRequest(request);

  // Require authentication before accepting the request
  if (request.authenticatedUserId === null) {
    errors.push({
      field: "authenticatedUserId",
      message: "An authenticated user is required.",
    });
  }

  return {
    accepted: errors.length === 0,
    errors,
  };
}
