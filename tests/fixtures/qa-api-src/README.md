# qa-api-src fixture

The source tree behind the `qa-api` fixture server (`../qa-api/server.py`), split by route group
the way a real service is, with the same routes as `../qa-api/openapi.json`. It is never run: it
exists so the `agent-diff` eval suite (`tests/eval/agent-diff.toml`) has a code diff to plan from.

The harness builds a throwaway git repository from the two directories, in order:

| directory | commit | content |
|---|---|---|
| `base/` | 1 (tagged `base`) | one handler file per route group, plus docs |
| `change/` | 2 | the PR: `app/search.py` changes (the query is now built with a `LIKE` filter, still by string formatting) and the changelog grows |

So `git diff base...HEAD` names `app/search.py` and `docs/CHANGELOG.md`. The first maps to
`GET /search` (a route the extractors read from its decorator); the second maps to no operation.
The seeded bug behind `GET /search` is number 4 of `server.py` (a quote in `q` answers 500 with a
traceback), so a run that plans around the change must find it without testing the other routes.

Routes are written as Flask-style decorators (`@app.get("/orders/<int:id>")`), one of the shapes
`qa::suite::extract_routes` understands.
