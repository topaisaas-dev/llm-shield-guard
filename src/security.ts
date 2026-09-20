/**
 * Security & Input Validation Module for LLM Shield & Prompt Guard API
 */

export const MAX_PROMPT_LENGTH = 100_000; // 100k chars max per request

export function sanitizeInput(input: unknown): string {
  if (typeof input !== "string") {
    throw new Error("Missing or invalid 'prompt' field. Expected a string.");
  }

  const trimmed = input.trim();
  if (trimmed.length === 0) {
    throw new Error("Field 'prompt' cannot be empty.");
  }

  if (trimmed.length > MAX_PROMPT_LENGTH) {
    throw new Error(`Prompt exceeds maximum length of ${MAX_PROMPT_LENGTH} characters.`);
  }

  return trimmed;
}

export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
