/**
 * LLM Shield Core Detection & Sanitization Engine
 */

import { INJECTION_RULES, PII_PATTERNS, passesLuhn } from "./patterns";
import type { ShieldScanRequest, ShieldScanResponse, ThreatDetail, PIIDetail, ValidateOutputRequest, ValidateOutputResponse } from "./types";

/**
 * Scans input prompt for security threats, jailbreaks, and sensitive PII.
 */
export function scanPrompt(req: ShieldScanRequest): ShieldScanResponse {
  const start = Date.now();
  const prompt = req.prompt || "";
  const detectInjection = req.detect_injection !== false;
  const redactPii = req.redact_pii !== false;
  const maskMode = req.mask_mode || "placeholder";
  const threshold = req.threshold !== undefined ? req.threshold : 40;

  const threats: ThreatDetail[] = [];
  const piiList: PIIDetail[] = [];
  let score = 0;

  // 1. Scan for Injections and Jailbreaks
  if (detectInjection) {
    for (const rule of INJECTION_RULES) {
      const match = prompt.match(rule.pattern);
      if (match) {
        threats.push({
          category: rule.category,
          rule_id: rule.id,
          severity: rule.severity,
          description: rule.description,
          matched_text: match[0].slice(0, 80)
        });
        score += rule.weight;
      }
    }
  }

  // 2. Scan and Mask PII
  let sanitized = prompt;

  if (redactPii) {
    // A. Credit Cards (with Luhn validation)
    const cardMatches = prompt.match(PII_PATTERNS.CREDIT_CARD_CANDIDATE) || [];
    let validCards = 0;
    for (const card of cardMatches) {
      const cleanDigits = card.replace(/[-\s]/g, "");
      if (passesLuhn(cleanDigits)) {
        validCards++;
        const replacement = maskMode === "asterisks"
          ? `****-****-****-${cleanDigits.slice(-4)}`
          : `[REDACTED_CREDIT_CARD]`;
        sanitized = sanitized.replace(card, replacement);
      }
    }
    if (validCards > 0) {
      piiList.push({ type: "credit_card", count: validCards, sample_masked: "[REDACTED_CREDIT_CARD]" });
      score += 15;
    }

    // B. Email Addresses
    const emailMatches = prompt.match(PII_PATTERNS.EMAIL) || [];
    if (emailMatches.length > 0) {
      for (const email of emailMatches) {
        const replacement = maskMode === "anonymize"
          ? "user_anon@example.com"
          : "[REDACTED_EMAIL]";
        sanitized = sanitized.replace(email, replacement);
      }
      piiList.push({ type: "email", count: emailMatches.length, sample_masked: "[REDACTED_EMAIL]" });
      score += 5;
    }

    // C. Phone Numbers
    const phoneMatches = prompt.match(PII_PATTERNS.PHONE) || [];
    if (phoneMatches.length > 0) {
      for (const phone of phoneMatches) {
        if (phone.trim().length >= 7) {
          sanitized = sanitized.replace(phone, "[REDACTED_PHONE]");
        }
      }
      piiList.push({ type: "phone", count: phoneMatches.length, sample_masked: "[REDACTED_PHONE]" });
      score += 5;
    }

    // D. US Social Security Numbers
    const ssnMatches = prompt.match(PII_PATTERNS.SSN) || [];
    if (ssnMatches.length > 0) {
      for (const ssn of ssnMatches) {
        sanitized = sanitized.replace(ssn, "[REDACTED_SSN]");
      }
      piiList.push({ type: "ssn", count: ssnMatches.length, sample_masked: "[REDACTED_SSN]" });
      score += 25;
    }

    // E. API Keys & Secrets
    const apiKeys: string[] = [
      ...(prompt.match(PII_PATTERNS.API_KEY_OPENAI) || []),
      ...(prompt.match(PII_PATTERNS.API_KEY_GITHUB) || []),
      ...(prompt.match(PII_PATTERNS.API_KEY_AWS) || []),
      ...(prompt.match(PII_PATTERNS.API_KEY_STRIPE) || []),
      ...(prompt.match(PII_PATTERNS.JWT_TOKEN) || [])
    ];
    if (apiKeys.length > 0) {
      for (const key of apiKeys) {
        sanitized = sanitized.replace(key, "[REDACTED_SECRET_KEY]");
      }
      piiList.push({ type: "api_key", count: apiKeys.length, sample_masked: "[REDACTED_SECRET_KEY]" });
      score += 35;
    }
  }

  // Cap score between 0 and 100
  const normalizedScore = Math.min(score, 100);

  // Verdict decision
  let action: "allow" | "sanitize" | "block" = "allow";
  if (normalizedScore >= threshold || threats.some(t => t.severity === "critical")) {
    action = "block";
  } else if (piiList.length > 0 || threats.length > 0) {
    action = "sanitize";
  }

  return {
    is_safe: action === "allow",
    risk_score: normalizedScore,
    action_recommended: action,
    threats_detected: threats,
    pii_detected: piiList,
    sanitized_prompt: action === "block" ? "[BLOCKED_BY_LLM_SHIELD]" : sanitized,
    execution_time_ms: Date.now() - start
  };
}

/**
 * Validates model output to ensure internal instructions or environment keys were not leaked.
 */
export function validateOutput(req: ValidateOutputRequest): ValidateOutputResponse {
  const output = req.llm_output || "";
  const leaks: string[] = [];
  let sanitized = output;

  // Check if system prompt phrases leaked
  if (req.system_prompt) {
    const lines = req.system_prompt.split("\n").filter(l => l.trim().length > 25);
    for (const line of lines) {
      if (output.includes(line.trim())) {
        leaks.push("Direct verbatim leakage of system instruction sentence.");
        sanitized = sanitized.replace(line.trim(), "[SYSTEM_PROMPT_LEAK_MASKED]");
      }
    }
  }

  // Check for leaked API keys in response
  const leakedKeys = [
    ...(output.match(PII_PATTERNS.API_KEY_OPENAI) || []),
    ...(output.match(PII_PATTERNS.API_KEY_GITHUB) || []),
    ...(output.match(PII_PATTERNS.API_KEY_AWS) || []),
    ...(output.match(PII_PATTERNS.API_KEY_STRIPE) || [])
  ];

  for (const k of leakedKeys) {
    leaks.push(`Detected exposed credential (${k.slice(0, 4)}***)`);
    sanitized = sanitized.replace(k, "[REDACTED_SECRET_LEAK]");
  }

  return {
    is_leak_detected: leaks.length > 0,
    leak_details: leaks,
    sanitized_output: sanitized
  };
}
