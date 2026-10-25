# qa-api fixture

Stdlib-only Python API with seeded bugs (see the docstring in `server.py`):
IDOR on `/orders/{id}`, unauthenticated `/admin/stats`, 500 on `note` > 100 chars, traceback
leak on `/search?q='`, missing required `total` on `/orders/2`, no-op `DELETE`, slow `/reports/slow`.

    python3 server.py 18090 /tmp/rh-requests.log &      # log = one "METHOD /path" line per request
    export RH_ALICE_TOKEN=alice-token RH_BOB_TOKEN=bob-token RH_ADMIN_TOKEN=admin-token   # fake fixture values
    readyhai qa http://127.0.0.1:18090 --spec openapi.json --roles roles.toml --scope scope.toml --profile standard

`scope.toml` must list 127.0.0.1 and tag it `env = "nonprod"` for write tests; tag it `prod` (or omit the tag)
and the request log must contain only GET lines.
