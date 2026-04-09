# NSEC2: Request Schema Validation Gateway

Build a reusable request boundary that validates method, shape, and body limits before application logic runs.

## Goals

- reject malformed or oversized requests early
- produce consistent validation errors
- separate boundary validation from later authorization logic
