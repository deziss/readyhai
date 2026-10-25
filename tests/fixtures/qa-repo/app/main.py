from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/orders")
def list_orders():
    return []


@app.get("/orders/{id}")
def get_order(id: int):
    return {"id": id}


@app.get("/admin/stats")
def admin_stats():
    return {"orders": 0}
