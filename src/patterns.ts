/**
 * Threat Patterns & Algorithmic Signatures for Prompt Injections, Jailbreaks & PII
 */

import type { ThreatDetail, PIIDetail } from "./types";

/**
 * 1. Prompt Injection & Jailbreak Signatures
 */
export const INJECTION_RULES: Array<{
  id: string;
  category: ThreatDetail["category"];
  severity: ThreatDetail["severity"];
  weight: number;
  pattern: RegExp;
  description: string;
}> = [
  // Override & Ignore Directives
  {
    id: "OVERRIDE_IGNORE_INSTRUCTIONS",
    category: "prompt_injection",
    severity: "critical",
    weight: 45,
    pattern: /(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|existing|system)\s+(?:instructions|prompts|rules|directives|constraints)/i,
    description: "Explicit attempt to discard system prompt instructions"
  },
  {
    id: "SYSTEM_OVERRIDE_DIRECTIVE",
    category: "system_override",
    severity: "critical",
    weight: 40,
    pattern: /\[(?:system|instruction|developer|admin)(?:\s+override)?\]|<<SYS>>|<\|im_start\|>system|<\|start_header_id\|>system/i,
    description: "Attempt to fake system token boundaries or chat markup tags"
  },
  {
    id: "EXFILTRATE_SYSTEM_PROMPT",
    category: "prompt_injection",
    severity: "high",
    weight: 35,
    pattern: /(?:repeat|print|output|reveal|display|show|quote)\s+(?:the\s+)?(?:system\s+prompt|initial\s+prompt|instructions\s+above|hidden\s+rules|system\s+message)\s+(?:verbatim|word\s+for\s+word|completely)?/i,
    description: "Attempt to extract secret system prompt or internal guidelines"
  },
  // Jailbreak Personas & DAN Modes
  {
    id: "DAN_JAILBREAK_PERSONA",
    category: "jailbreak",
    severity: "critical",
    weight: 50,
    pattern: /\b(?:DAN|Do\s+Anything\s+Now|STAN|DUDE|AIM|Jailbreak|UnfilteredAI|DevMode)\b(?:\s+mode)?/i,
    description: "Classic DAN / Do Anything Now jailbreak persona injection"
  },
  {
    id: "UNRESTRICTED_ROLEPLAY",
    category: "jailbreak",
    severity: "high",
    weight: 35,
    pattern: /(?:you\s+are\s+now|pretend\s+you\s+are|act\s+as)\s+(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|evil|unethical|amoral)\s+(?:ai|model|assistant|bot)/i,
    description: "Unfiltered / amoral persona switch attempt"
  },
  {
    id: "ALWAYS_SAY_YES_COERCION",
    category: "jailbreak",
    severity: "medium",
    weight: 25,
    pattern: /(?:you\s+must\s+always|you\s+cannot\s+refuse|never\s+say\s+no|comply\s+with\s+every\s+request)/i,
    description: "Coercive constraint override forcing unconditional agreement"
  },
  // Encoding & Obfuscation vectors
  {
    id: "BASE64_EXEC_INJECTION",
    category: "encoded_attack",
    severity: "high",
    weight: 30,
    pattern: /(?:decode|execute|run|eval)\s+(?:this\s+)?(?:base64|hex|rot13):\s*[a-zA-Z0-9+/=]{30,}/i,
    description: "Obfuscated payload injection via encoded text wrapper"
  },
  {
    id: "ZERO_WIDTH_INVISIBLE_INJECTION",
    category: "encoded_attack",
    severity: "high",
    weight: 35,
    pattern: /[\u200B-\u200D\uFEFF\uE0000-\uE007F]{3,}/,
    description: "Invisible zero-width or Unicode tag character injection attack"
  }
];

/**
 * 2. Luhn Algorithm Check for Credit Cards
 */
export function passesLuhn(digitsOnly: string): boolean {
  if (!/^\d{13,19}$/.test(digitsOnly)) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digitsOnly.length - 1; i >= 0; i--) {
    let digit = parseInt(digitsOnly.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * 3. PII Detection Patterns
 */
export const PII_PATTERNS = {
  EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  PHONE: /(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b/g,
  SSN: /\b\d{3}-\d{2}-\d{4}\b/g,
  CREDIT_CARD_CANDIDATE: /\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,19}\b/g,
  API_KEY_OPENAI: /sk-(?:live-)?[a-zA-Z0-9]{32,48}/g,
  API_KEY_GITHUB: /gh[pousr]_[a-zA-Z0-9]{36}/g,
  API_KEY_AWS: /AKIA[0-9A-Z]{16}/g,
  API_KEY_STRIPE: /(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}/g,
  JWT_TOKEN: /\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g
};
