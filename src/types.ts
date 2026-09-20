export type Severity = "low" | "medium" | "high" | "critical";

export interface ThreatDetail {
  category: "prompt_injection" | "jailbreak" | "system_override" | "pii_leak" | "harmful_content" | "encoded_attack";
  rule_id: string;
  severity: Severity;
  description: string;
  matched_text?: string;
}

export interface PIIDetail {
  type: "credit_card" | "email" | "phone" | "ssn" | "api_key" | "jwt_token";
  count: number;
  sample_masked: string;
}

export interface ShieldScanRequest {
  prompt: string;
  detect_injection?: boolean;
  redact_pii?: boolean;
  detect_harmful?: boolean;
  mask_mode?: "placeholder" | "anonymize" | "asterisks";
  threshold?: number; // 0 - 100 risk score
}

export interface ShieldScanResponse {
  is_safe: boolean;
  risk_score: number; // 0 to 100
  action_recommended: "allow" | "sanitize" | "block";
  threats_detected: ThreatDetail[];
  pii_detected: PIIDetail[];
  sanitized_prompt: string;
  execution_time_ms: number;
}

export interface ValidateOutputRequest {
  system_prompt?: string;
  llm_output: string;
}

export interface ValidateOutputResponse {
  is_leak_detected: boolean;
  leak_details: string[];
  sanitized_output: string;
}
