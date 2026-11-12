# ReadyHai eval: PASS

version 0.8.0 · 2026-11-12T03:14:18.414246775Z · k = 2

| suite | kind | recall | min run | precision | FP | inconclusive | confidence | pass^k | verdict | requests | time | open gaps | result |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| agent-api | Agent | 1.00 | 1.00 | 1.00 | 0 | 6% | 93% | yes | NO_GO | 170 | 22.1s | 0 | PASS |
| agent-diff | Agent | 1.00 | 1.00 | 1.00 | 0 | 0% | 100% | yes | CONDITIONAL_GO | 20 | 2.0s | 0 | PASS |
| agent-memory | Agent | 1.00 | 1.00 | 1.00 | 0 | 5% | 95% | yes | NO_GO | 340 | 44.0s | 0 | PASS |
| agent-spa-clean | Agent | 1.00 | 1.00 | 1.00 | 0 | 24% | 76% | yes | CONDITIONAL_GO | 81 | 7.9s | 0 | PASS |
| agent-spa-noauth | Agent | 1.00 | 1.00 | 1.00 | 0 | 0% | 60% | yes | NOT_EVALUATED | 68 | 6.7s | 0 | PASS |
| agent-spa | Agent | 1.00 | 1.00 | 1.00 | 0 | 17% | 83% | yes | NO_GO | 106 | 10.1s | 0 | PASS |
| qa-api | Qa | 1.00 | 1.00 | 1.00 | 0 | - | - | yes | NoGo/Fail | 123 | 31.8s | 0 | PASS |
| qa-repo | Repo | 1.00 | 1.00 | 1.00 | 0 | - | - | yes | Warn | 0 | 0.1s | 0 | PASS |
| security-deep | Agent | 1.00 | 1.00 | 1.00 | 0 | 10% | 89% | yes | NO_GO | 258 | 34.4s | 0 | PASS |
| whitebox-exploit | Agent | 1.00 | 1.00 | 1.00 | 0 | 0% | 100% | yes | NO_GO | 55 | 5.5s | 0 | PASS |

## agent-api (PASS)

Autonomous agent vs the 7 seeded bugs of the qa-api fixture

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 0.85
- PASS false positives: worst run 0 vs <= 2
- PASS pass^k: 2/2 runs at recall >= 0.85
- PASS verdict stable: NO_GO | NO_GO
- PASS expected verdict: want NO_GO, got NO_GO | NO_GO
- PASS request budget: worst run 170 vs <= 250
- PASS time budget: worst run 22.1s vs <= 120s
- run 1 cases: FAIL 22, INCONCLUSIVE 4, PASS 39, SKIPPED 4
- run 2 cases: FAIL 22, INCONCLUSIVE 4, PASS 39, SKIPPED 4

## agent-diff (PASS)

A PR that touches one route: the agent plans that operation first, in full, and finds its bug

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 0.85
- PASS false positives: worst run 0 vs <= 0
- PASS pass^k: 2/2 runs at recall >= 0.85
- PASS verdict stable: CONDITIONAL_GO | CONDITIONAL_GO
- PASS expected verdict: want CONDITIONAL_GO, got CONDITIONAL_GO | CONDITIONAL_GO
- PASS request budget: worst run 20 vs <= 40
- PASS time budget: worst run 2.0s vs <= 30s
- PASS changed operations: 2 changed file(s) -> reported [GET /search], expected [GET /search]
- PASS changed operations planned first: 5 changed case(s), the last at position 5; the first other case at 6
- PASS changed operations covered: 5 of 5 planned case(s) sent (100%) vs >= 100%
- run 1 cases: FAIL 1, PASS 7
- run 2 cases: FAIL 1, PASS 7

## agent-memory (PASS)

The agent remembers the 7 seeded bugs between two runs in one data directory: still open, probes first

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 0.85
- PASS false positives: worst run 0 vs <= 2
- PASS pass^k: 2/2 runs at recall >= 0.85
- PASS verdict stable: NO_GO | NO_GO
- PASS expected verdict: want NO_GO, got NO_GO | NO_GO
- PASS request budget: worst run 340 vs <= 500
- PASS time budget: worst run 44.0s vs <= 240s
- PASS memory: first run remembered: first_run true, remembered true, 7 new of 7 defect(s)
- PASS memory: seeded defects still open: 7 of 7 expected defect(s) reported still open (7 defect(s) in all)
- PASS memory: regression probes lead the plan: 17 probe(s) lead the plan of 55 case(s), none after the first other case; 6 of 6 still-open defect(s) have one
- PASS memory: no case dropped: run 1 planned 54 case(s), the last run 55 (1 more)
- run 1 cases: FAIL 22, INCONCLUSIVE 3, PASS 40, SKIPPED 5
- run 2 cases: FAIL 22, INCONCLUSIVE 3, PASS 40, SKIPPED 5

## agent-spa-clean (PASS)

Autonomous agent vs the bug-free spa-next fixture: no false NO_GO

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 0.85
- PASS false positives: worst run 0 vs <= 1
- PASS pass^k: 2/2 runs at recall >= 0.85
- PASS verdict stable: CONDITIONAL_GO | CONDITIONAL_GO
- PASS forbidden verdict: must not be NO_GO, got CONDITIONAL_GO | CONDITIONAL_GO
- PASS inconclusive rate: worst run 24% vs <= 25%
- PASS request budget: worst run 81 vs <= 300
- PASS time budget: worst run 7.9s vs <= 120s
- run 1 cases: INCONCLUSIVE 4, PASS 13
- run 2 cases: INCONCLUSIVE 4, PASS 13

## agent-spa-noauth (PASS)

Autonomous agent vs the spa-next fixture without credentials: NOT_EVALUATED with an auth-wall blocker

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 0.85
- PASS false positives: worst run 0 vs <= 0
- PASS pass^k: 2/2 runs at recall >= 0.85
- PASS verdict stable: NOT_EVALUATED | NOT_EVALUATED
- PASS expected verdict: want NOT_EVALUATED, got NOT_EVALUATED | NOT_EVALUATED
- PASS expected blocker: want auth_wall in every run, got [auth_wall] [auth_wall]
- PASS request budget: worst run 68 vs <= 300
- PASS time budget: worst run 6.7s vs <= 120s
- blockers reported: auth_wall
- run 1 cases: BLOCKED 4, PASS 6, SKIPPED 1
- run 2 cases: BLOCKED 4, PASS 6, SKIPPED 1

## agent-spa (PASS)

Autonomous agent vs the 3 seeded bugs of the spa-next fixture (SPA behind a login wall, no spec, test accounts given)

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 0.85
- PASS false positives: worst run 0 vs <= 2
- PASS pass^k: 2/2 runs at recall >= 0.85
- PASS verdict stable: NO_GO | NO_GO
- PASS expected verdict: want NO_GO, got NO_GO | NO_GO
- PASS inconclusive rate: worst run 17% vs <= 25%
- PASS request budget: worst run 106 vs <= 300
- PASS time budget: worst run 10.1s vs <= 120s
- run 1 cases: FAIL 3, INCONCLUSIVE 3, PASS 12
- run 2 cases: FAIL 3, INCONCLUSIVE 3, PASS 12

## qa-api (PASS)

QA engine vs the 7 seeded bugs of the qa-api fixture

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 0.85
- PASS false positives: worst run 0 vs <= 2
- PASS pass^k: 2/2 runs at recall >= 0.85
- PASS verdict stable: NoGo/Fail | NoGo/Fail
- PASS expected verdict: want NoGo/Fail, got NoGo/Fail | NoGo/Fail
- PASS request budget: worst run 123 vs <= 300
- PASS time budget: worst run 31.8s vs <= 150s

## qa-repo (PASS)

QA suite and release checks vs the seeded defects of the qa-repo fixture

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 0.85
- PASS false positives: worst run 0 vs <= 2
- PASS pass^k: 2/2 runs at recall >= 0.85
- PASS verdict stable: Warn | Warn
- PASS time budget: worst run 0.1s vs <= 60s
- run 1 optional not found: migration-failure
- run 2 optional not found: migration-failure

## security-deep (PASS)

Deep security benchmark against 12 seeded loopholes (Blind SQLi, SSTI, Blind SSRF, Open Redirect, JWT alg=none, BFLA, Mass Assignment, Negative Qty, TOCTOU, DOM XSS, Stored XSS) plus clean negative controls

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 0.85
- PASS false positives: worst run 0 vs <= 0
- PASS pass^k: 2/2 runs at recall >= 0.85
- PASS verdict stable: NO_GO | NO_GO
- PASS expected verdict: want NO_GO, got NO_GO | NO_GO
- PASS request budget: worst run 258 vs <= 500
- PASS time budget: worst run 34.4s vs <= 180s
- run 1 cases: FAIL 13, INCONCLUSIVE 11, PASS 81, SKIPPED 1
- run 2 cases: FAIL 13, INCONCLUSIVE 11, PASS 81, SKIPPED 1

## whitebox-exploit (PASS)

White-box repo audit discovers undocumented /internal/debug-export route, exploits its SQLi, and attaches file:line source linkage

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 1.00
- PASS false positives: worst run 0 vs <= 0
- PASS pass^k: 2/2 runs at recall >= 1.00
- PASS verdict stable: NO_GO | NO_GO
- PASS expected verdict: want NO_GO, got NO_GO | NO_GO
- PASS request budget: worst run 55 vs <= 200
- PASS time budget: worst run 5.5s vs <= 60s
- PASS whitebox source linkage: linked /internal/debug-export (app.py:9 handler `debug_export` for GET /internal/debug-export [sinks: sqli `conn.execute` (app.py:12)])
- run 1 cases: FAIL 1, PASS 7, SKIPPED 1
- run 2 cases: FAIL 1, PASS 7, SKIPPED 1
