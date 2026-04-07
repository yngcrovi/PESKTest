from fastapi import FastAPI, Depends
from fastapi.responses import JSONResponse
from uvicorn import run
from db.service.test import Test
from route.auth import route as auth

app = FastAPI(
    root_path='/api'
)

app.include_router(auth)

if __name__ == "__main__":
    run("app:app", host="0.0.0.0", port=8000, reload=True)