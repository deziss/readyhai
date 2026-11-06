# spa-next fixture

Stdlib-only Python server that looks, to a scanner, like a thin Next.js SPA behind a login wall
(see the docstring in `server.py` for the routes and the seeded bugs).

    python3 server.py 18091 /tmp/rh-requests.log            # buggy: IDOR, SQL error leak, 500 on bad paging
    python3 server.py 18091 /tmp/rh-requests.log --clean    # the same app with every bug fixed
    # fake fixture tokens: Authorization: Bearer alice-token | bob-token
    export RH_ALICE_TOKEN=alice-token RH_BOB_TOKEN=bob-token

There is no OpenAPI spec on purpose: the API is only reachable through the JS chunks
(`/_next/static/chunks/...`), `_buildManifest.js`, `sitemap.xml` and `robots.txt`. Used by the eval
suites `agent-spa`, `agent-spa-clean` and `agent-spa-noauth` (`docs/eval.md`).
