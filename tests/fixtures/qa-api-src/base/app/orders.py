from app import app, db, current_user


@app.get("/orders")
def list_orders():
    return db.orders_for(current_user())


@app.post("/orders")
def create_order(body):
    return db.insert_order(current_user(), body), 201


@app.get("/orders/<int:id>")
def get_order(id):
    return db.order(id)


@app.put("/orders/<int:id>")
def update_order(id, body):
    return db.update_order(id, body)


@app.delete("/orders/<int:id>")
def delete_order(id):
    db.delete_order(id)
    return "", 204
