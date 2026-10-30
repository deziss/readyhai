# resilience fixture

    docker compose up -d                      # app :18095 + redis
    # scope.toml:  [[hosts]] host="127.0.0.1" env="nonprod"
    #              [hosts.resilience] compose_project="rh-resil" services=["redis"]
    readyhai qa http://127.0.0.1:18095 --scope scope.toml --profile deep
    docker compose down

`RH_MODE=storm docker compose up -d` is the buggy variant (500 instead of 503 -> `qa.resilience.no_degraded_status`).
