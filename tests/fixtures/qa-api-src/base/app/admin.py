from app import app, db


@app.get("/admin/stats")
def stats():
    return {"orders": db.count_orders()}
