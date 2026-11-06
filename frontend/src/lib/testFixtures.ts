import type { EvidenceLedger } from "@/types/agent";

/**
 * An evidence ledger in the shape the backend serialises it (`evidence_ledger` of a run JSON):
 * `pillars[]` with a confidence, a `blockers[]` list and a NOT_EVALUATED verdict. Test data only.
 */
export const NOT_EVALUATED_LEDGER: EvidenceLedger = {
  value_score: 62,
  authority_score: null,
  safety_score: null,
  evidence_score: 100,
  overall_readiness: 0,
  gate_verdict: "NOT_EVALUATED",
  executive_summary: "Not evaluated: 18 case(s) planned, 4 conclusive (22%). Provide credentials to test the protected routes.",
  exit_criteria_checklist: [
    { criterion: "Conclusive coverage >= 80% of applicable cases", met: false, details: "22% conclusive" },
  ],
  composite_score: undefined,
  evaluated: false,
  confidence: 22,
  verdict_basis: "not evaluated: overall confidence 22% is below 50%",
  pillars: [
    {
      id: "value",
      name: "Functional correctness and input handling",
      score: 62,
      status: "partial",
      claim: "boundary: 2 passed, 1 failed of 3 conclusive",
      confidence: 40,
      techniques: ["boundary", "negative", "state_transition"],
      case_ids: ["TC-001", "TC-002", "TC-003"],
      evidence_files: ["evidence/TC-001.json"],
    },
    {
      id: "authority",
      name: "Authorization and least privilege",
      score: null,
      status: "not_evaluated",
      claim: "not evaluated: no conclusive result for authz (3 inconclusive, 5 blocked of 8 planned)",
      confidence: 0,
      techniques: ["authz"],
      case_ids: ["TC-004", "TC-005"],
      evidence_files: [],
    },
    {
      id: "safety",
      name: "Injection resistance and data safety",
      score: null,
      status: "not_evaluated",
      claim: "not evaluated: no conclusive result for injection",
      confidence: null,
      techniques: ["injection"],
      case_ids: [],
      evidence_files: [],
    },
    {
      id: "evidence",
      name: "Reproducible evidence",
      score: 100,
      status: "pass",
      claim: "4 of 4 executed cases have a stored request/response pair",
      confidence: null,
      techniques: [],
      case_ids: [],
      evidence_files: [],
    },
  ],
  coverage: [
    {
      technique: "injection",
      planned: 0,
      pass: 0,
      warn: 0,
      fail: 0,
      inconclusive: 0,
      blocked: 0,
      skipped: 0,
      not_applicable: 6,
    },
  ],
  blockers: [
    {
      reason: "auth_wall",
      detail: "https://agent-prod.nuhire.in/ answers 307 to /login: 12 case(s) need a signed-in session.",
      next_step: "Provide test accounts: readyhai roles init --spec <openapi> (or a storageState login).",
      case_ids: ["TC-004", "TC-005", "TC-006"],
    },
    {
      reason: "no_surface",
      detail: "No API endpoint or form was found, so input-class techniques have nothing to exercise.",
      next_step: "Provide the OpenAPI spec URL of the API host.",
      case_ids: [],
    },
  ],
};
