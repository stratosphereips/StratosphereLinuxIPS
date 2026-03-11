from fastapi import FastAPI, Form
import uvicorn

app = FastAPI()


# Your existing POST logic for Zeek testing
@app.post("/login")
async def login(
    user: str = Form(...), password: str = Form(None, alias="pass")
):
    # Zeek logs the request/response pair even if we return a 401
    return {"status": "received"}


# Added GET handler for the same path
@app.get("/login")
async def get_login():
    return {"message": "Send a POST request with user/pass to test login"}


# Optional: Catch-all GET for the root path
@app.get("/")
async def read_root():
    return {"status": "server_is_up"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
