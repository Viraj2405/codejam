export interface AlertRecord {
  id: string;
  alert_type: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;
  status: "OPEN" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE" | string;
  user_id: string;
  description: string;
  event_refs: string[];
  evidence: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

