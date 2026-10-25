# Expected ReadyHai suite/release defects for qa-repo

- qa.suite.low_coverage (overall 42% < 60%)
- qa.suite.critical_uncovered (app/auth.py at 0%)
- qa.suite.untested_routes (/health, /orders/{id}, /admin/stats; only /orders is referenced by tests)
- qa.suite.test_smells (1 test without assert, 1 skipped, 1 sleep >= 1s)
- qa.release.eol_runtime (python:3.8 is EOL)
- qa.release.migration_failure (alembic downgrade raises NotImplementedError; needs [test] image)
