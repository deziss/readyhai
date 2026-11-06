# ReadyHai eval: PASS

version 0.5.0 · 2026-11-06T13:45:04.746493748Z · k = 2

| suite | kind | recall | min run | precision | FP | inconclusive | confidence | pass^k | verdict | requests | time | open gaps | result |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| agent-api | Agent | 1.00 | 1.00 | 1.00 | 0 | 8% | 92% | yes | NO_GO | 106 | 16.2s | 0 | PASS |
| agent-diff | Agent | 1.00 | 1.00 | 1.00 | 0 | 0% | 100% | yes | CONDITIONAL_GO | 20 | 2.0s | 0 | PASS |
| agent-memory | Agent | 1.00 | 1.00 | 1.00 | 0 | 8% | 92% | yes | NO_GO | 213 | 32.5s | 0 | PASS |
| agent-spa-clean | Agent | 1.00 | 1.00 | 1.00 | 0 | 25% | 75% | yes | CONDITIONAL_GO | 55 | 5.8s | 0 | PASS |
| agent-spa-noauth | Agent | 1.00 | 1.00 | 1.00 | 0 | 0% | 55% | yes | NOT_EVALUATED | 42 | 4.7s | 0 | PASS |
| agent-spa | Agent | 1.00 | 1.00 | 1.00 | 0 | 19% | 81% | yes | NO_GO | 79 | 7.9s | 0 | PASS |
| qa-api | Qa | 1.00 | 1.00 | 1.00 | 0 | - | - | yes | NoGo/Fail | 123 | 31.9s | 0 | PASS |
| qa-repo | Repo | 1.00 | 1.00 | 1.00 | 0 | - | - | yes | Warn | 0 | 0.1s | 0 | PASS |

## agent-api (PASS)

Autonomous agent vs the 7 seeded bugs of the qa-api fixture

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 0.85
- PASS false positives: worst run 0 vs <= 2
- PASS pass^k: 2/2 runs at recall >= 0.85
- PASS verdict stable: NO_GO | NO_GO
- PASS expected verdict: want NO_GO, got NO_GO | NO_GO
- PASS request budget: worst run 106 vs <= 250
- PASS time budget: worst run 16.2s vs <= 120s
- run 1 cases: FAIL 15, INCONCLUSIVE 4, PASS 33
- run 2 cases: FAIL 15, INCONCLUSIVE 4, PASS 33

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
- PASS request budget: worst run 213 vs <= 500
- PASS time budget: worst run 32.5s vs <= 240s
- PASS memory: first run remembered: first_run true, remembered true, 7 new of 7 defect(s)
- PASS memory: seeded defects still open: 7 of 7 expected defect(s) reported still open (7 defect(s) in all)
- PASS memory: regression probes lead the plan: 13 probe(s) lead the plan of 42 case(s), none after the first other case; 6 of 6 still-open defect(s) have one
- PASS memory: no case dropped: run 1 planned 41 case(s), the last run 42 (1 more)
- run 1 cases: FAIL 15, INCONCLUSIVE 4, PASS 34
- run 2 cases: FAIL 15, INCONCLUSIVE 4, PASS 34

## agent-spa-clean (PASS)

Autonomous agent vs the bug-free spa-next fixture: no false NO_GO

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 0.85
- PASS false positives: worst run 0 vs <= 1
- PASS pass^k: 2/2 runs at recall >= 0.85
- PASS verdict stable: CONDITIONAL_GO | CONDITIONAL_GO
- PASS forbidden verdict: must not be NO_GO, got CONDITIONAL_GO | CONDITIONAL_GO
- PASS inconclusive rate: worst run 25% vs <= 25%
- PASS request budget: worst run 55 vs <= 300
- PASS time budget: worst run 5.8s vs <= 120s
- run 1 cases: INCONCLUSIVE 4, PASS 12
- run 2 cases: INCONCLUSIVE 4, PASS 12

## agent-spa-noauth (PASS)

Autonomous agent vs the spa-next fixture without credentials: NOT_EVALUATED with an auth-wall blocker

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 0.85
- PASS false positives: worst run 0 vs <= 0
- PASS pass^k: 2/2 runs at recall >= 0.85
- PASS verdict stable: NOT_EVALUATED | NOT_EVALUATED
- PASS expected verdict: want NOT_EVALUATED, got NOT_EVALUATED | NOT_EVALUATED
- PASS expected blocker: want auth_wall in every run, got [auth_wall] [auth_wall]
- PASS request budget: worst run 42 vs <= 300
- PASS time budget: worst run 4.7s vs <= 120s
- blockers reported: auth_wall
- run 1 cases: BLOCKED 4, PASS 5, SKIPPED 1
- run 2 cases: BLOCKED 4, PASS 5, SKIPPED 1

## agent-spa (PASS)

Autonomous agent vs the 3 seeded bugs of the spa-next fixture (SPA behind a login wall, no spec, test accounts given)

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 0.85
- PASS false positives: worst run 0 vs <= 2
- PASS pass^k: 2/2 runs at recall >= 0.85
- PASS verdict stable: NO_GO | NO_GO
- PASS expected verdict: want NO_GO, got NO_GO | NO_GO
- PASS inconclusive rate: worst run 19% vs <= 25%
- PASS request budget: worst run 79 vs <= 300
- PASS time budget: worst run 7.9s vs <= 120s
- run 1 cases: FAIL 3, INCONCLUSIVE 3, PASS 10
- run 2 cases: FAIL 3, INCONCLUSIVE 3, PASS 10

## qa-api (PASS)

QA engine vs the 7 seeded bugs of the qa-api fixture

- PASS runs completed: 2/2 completed
- PASS recall: mean 1.000 (min run 1.000) vs >= 0.85
- PASS false positives: worst run 0 vs <= 2
- PASS pass^k: 2/2 runs at recall >= 0.85
- PASS verdict stable: NoGo/Fail | NoGo/Fail
- PASS expected verdict: want NoGo/Fail, got NoGo/Fail | NoGo/Fail
- PASS request budget: worst run 123 vs <= 300
- PASS time budget: worst run 31.9s vs <= 150s

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
