export type CandidateKind =
  | 'keyboard'
  | 'clipboard'
  | 'microphone'
  | 'credentials'
  | 'credential_logging'
  | 'network'
  | 'process'
  | 'filesystem'
  | 'dynamic_code'
  | 'tracking'
  | 'system_access'
  | 'persistence'
  | 'obfuscation'
  | 'supply_chain'
  | 'destructive'
  | 'security'
  | 'semgrep'

/** A static-search anchor. It is a lead for an agent to investigate, not a finding. */
export type Candidate = {
  kind: CandidateKind
  file: string
  line: number
  text: string
  rule?: string
}

/** Exact source evidence. The verifier must be able to reopen every location. */
export type Evidence = {
  file: string
  startLine: number
  endLine: number
  note: string
}

export type Finding = {
  kind: 'suspicious_behavior' | 'security_issue'
  title: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  confidence: 'low' | 'medium' | 'high'
  description: string
  evidence: Evidence[]
  /** Optional source -> transformation(s) -> sink path when the code proves one. */
  flow?: {
    source?: Evidence
    transformations?: Evidence[]
    sink?: Evidence
  }
}

export type AgentReport = {
  summary: string
  findings: Finding[]
  inspectedFiles: string[]
}

/**
 * The intentionally small V2 handoff. `candidates` are deterministic search
 * anchors, `investigation` is an untrusted draft, and `findings` are the fresh
 * verifier's final, source-cited conclusions.
 */
export type CheckV2Result = {
  commitSha: string
  candidates: Candidate[]
  investigation: AgentReport | null
  findings: Finding[]
  summary: string
}

export type AgentConfig = {
  provider: string
  model: string
  apiKey: string
  piKeyEnv: string
}
