# token_manager.py
import hashlib
import uuid
from datetime import datetime
from fastapi import Request, HTTPException, status, Header, Cookie
from jose import jwt, JWTError
from time import time
from redis import Redis
from env import env
from uuid import UUID

class TokenManager:
    """
    Полноценный менеджер токенов с поддержкой:
    - Белого и чёрного списков
    - Fingerprint устройств
    - Обнаружения кражи токенов
    - Rate limiting
    """
    
    def __init__(self, redis_client: Redis):
        self.key = env.SECRET_KEY
        self.algorithm = env.TOKEN_ALGORITHM
        self.access_exp = env.ACCESS_TOKEN_EXP_SECOND
        self.session_exp = env.SESSION_EXP
        self.redis = redis_client
        
        # Настройки безопасности
        self.max_sessions_per_user = 3  # максимум активных сессий
        self.enable_fingerprint = True   # проверять fingerprint
        self.enable_whitelist = True     # использовать белый список
    
    # ================================================
    # 1. Генерация fingerprint устройства
    # ================================================
    def generate_device_fingerprint(self, request: Request) -> str:
        """Генерация уникального отпечатка устройства"""
        fingerprint_data = [
            request.headers.get('user-agent', 'unknown'),
            request.headers.get('accept-language', 'unknown'),
            request.client.host if request.client else 'unknown',
            request.headers.get('sec-ch-ua', 'unknown'),
            request.headers.get('sec-ch-ua-platform', 'unknown'),
            request.headers.get('sec-ch-ua-mobile', 'unknown'),
        ]
        
        fingerprint_string = '|'.join(fingerprint_data)

        return hashlib.sha256(fingerprint_string.encode()).hexdigest()
    
    # ================================================
    # 2. Создание токенов с защитой
    # ================================================
    async def create_access_token(
        self, 
        user_id: int, 
        request: Request,
    ) -> dict:
        """Создание access токена с fingerprint и whitelist"""
        
        token_id = str(uuid.uuid4())
        fingerprint = self.generate_device_fingerprint(request)
        
        payload = {
            "sub": str(user_id),
            "jwt_id": token_id,  # Уникальный ID токена
            "fingerprint": fingerprint,
            "type": "access",
            "iat": int(time()),
            "exp": int(time()) + self.access_exp,
        }
        
        token = jwt.encode(payload, self.key, algorithm=self.algorithm)
        
        # Сохраняем в белый список Redis
        if self.enable_whitelist:
            whitelist_data = {
                "user_id": str(user_id),
                "fingerprint": fingerprint,
                "created_at": datetime.now().isoformat(),
                "ip": request.client.host if request.client else "unknown",
                "user_agent": request.headers.get('user-agent', 'unknown')[:200]
            }

            await self.redis.hset(f"whitelist:{token_id}", mapping=whitelist_data)
            await self.redis.expire(f"whitelist:{token_id}", self.access_exp)
            
            # Добавляем в список сессий пользователя
            await self.redis.sadd(f"user_sessions:{user_id}", token_id)
            await self.redis.expire(f"user_sessions:{user_id}", self.session_exp)
            
            # Ограничиваем количество активных сессий
            await self._limit_user_sessions(user_id)
        
        return {"id": token_id, "token": token}
    
    async def _limit_user_sessions(self, user_id: int):
        """Ограничение количества активных сессий пользователя"""
        sessions = await self.redis.smembers(f"user_sessions:{user_id}")
        
        if len(sessions) > self.max_sessions_per_user:
            # Удаляем самую старую сессию
            sessions_list = list(sessions)
            oldest_session = sessions_list[0]
            
            await self.revoke_token(oldest_session, reason="session_limit")
            await self.redis.srem(f"user_sessions:{user_id}", oldest_session)

    async def delete_user_session(self, user_id: UUID):
        await self.redis.delete(f"user_sessions:{user_id}")
    
    # ================================================
    # 3. Верификация токенов с проверкой fingerprint
    # ================================================
    async def decode_and_verify_token(
        self, 
        token: str, 
        request: Request,
        token_type: str = "access"
    ) -> dict:
        """
        Декодирование и верификация токена с проверкой:
        - Подписи
        - Срока действия
        - Белого списка
        - Fingerprint устройства
        - Чёрного списка
        """
        payload = {}
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="The user is not logged in"
            )
        # Базовая верификация JWT
        try:
            payload = jwt.decode(
                token, 
                self.key, 
                algorithms=[self.algorithm],
                options={"verify_exp": True}
            )
        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}"
            ) 
                
        
        # Проверка типа токена
        if payload.get("type") != token_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token type, expected {token_type}"
            )
        
        token_id = payload.get("jwt_id")
        if not token_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing jwt_id claim"
            )
        
        # Проверка чёрного списка
        if await self.redis.exists(f"blacklist:{token_id}"):
            blacklist_info = await self.redis.get(f"blacklist:{token_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token revoked: {blacklist_info}"
            )
        
        # Проверка белого списка 
        if token_type == "access" and self.enable_whitelist:
            if not await self.redis.exists(f"whitelist:{token_id}"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token not in whitelist"
                )
        
        # Проверка fingerprint 
        if self.enable_fingerprint and token_type == "access":
            current_fingerprint = self.generate_device_fingerprint(request)
            token_fingerprint = payload.get("fingerprint")
            
            if token_fingerprint != current_fingerprint:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Security violation: device fingerprint mismatch"
                )
        
        return payload
    
    
    # ================================================
    # 4. Управление чёрным списком
    # ================================================
    async def revoke_token(self, token_id: str, reason: str = "revoked"):
        """Отзыв токена (добавление в чёрный список)"""
        
        # Получаем информацию о токене из белого списка
        token_info = await self.redis.hgetall(f"whitelist:{token_id}")
        
        # Вычисляем оставшееся время жизни
        remaining_ttl = await self.redis.ttl(f"whitelist:{token_id}")
        
        # Добавляем в чёрный список
        await self.redis.setex(
            f"blacklist:{token_id}", 
            max(remaining_ttl, 300),  # минимум 5 минут
            f"revoked_at:{datetime.now().isoformat()}|reason:{reason}"
        )
        
        # Удаляем из белого списка
        await self.redis.delete(f"whitelist:{token_id}")
        
        # Удаляем из сессий пользователя
        if token_info and "user_id" in token_info:
            await self.redis.srem(f"user_sessions:{token_info['user_id']}", token_id)
