import time

from app import app


@app.get("/reports/slow")
def slow_report():
    time.sleep(1.5)
    return {"ok": True}
