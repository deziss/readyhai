from app import app, db


@app.get("/search")
def search(q):
    # the query is spliced into the SQL text
    return {"results": db.execute("SELECT * FROM items WHERE name = '%s'" % q), "q": q}
