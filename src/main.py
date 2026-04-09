from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from uvicorn import run
import redis.asyncio as redis
from route import auth, role, content
from contextlib import asynccontextmanager
from auth.token import TokenManager
from env import env

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Подключение к Redis
    app.state.redis = await redis.from_url(
        f"redis://{env.REDIS_HOST}:{env.REDIS_PORT}/0",
        decode_responses=True
    )
    print("Connected to Redis")
    app.state.token_manager = TokenManager(app.state.redis)
    yield
    await app.state.redis.aclose()
    print("Disconnected from Redis")

origins = [
    'http://localhost:8000',
    'http://127.0.0.1:8000',
    'http://0.0.0.0:8000'
]

app = FastAPI(
    root_path='/api',
    lifespan=lifespan
)
    
app.add_middleware(
    CORSMiddleware,
    allow_origins = origins,
    allow_credentials = True,
    allow_methods = ['*'],
    allow_headers = ['*'],
)

app.include_router(auth)
app.include_router(role)
app.include_router(content)

if __name__ == "__main__":
    run("main:app", host="0.0.0.0", port=8000, reload=True)