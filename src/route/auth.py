from fastapi import APIRouter

route = APIRouter(
    prefix='/auth',
    tags=['Auth']
)

@route.post('/login')
async def login():
    pass