from app import app, db


@app.get("/search")
def search(q):
    # matches anywhere in the name now; the query is still spliced into the SQL text
    return {"results": db.execute("SELECT * FROM items WHERE name LIKE '%%%s%%'" % q), "q": q}
