import os
from hashlib import pbkdf2_hmac
from env import env
# from db.model.auth import UserModel

class Password:
    def __init__(self) -> None:
        self.algorithm = env.PASSWORD_ALGORITHM
        self.iterations = env.NUMBER_OF_ITERATIONS

    def make_hash_password(self, password: str, salt: bytes) -> bytes:
        return pbkdf2_hmac(self.algorithm, password.encode('utf-8'), salt, self.iterations)

    # def get_hash_password(self, password: str, user_model: UserModel) -> UserModel:
    #     user_model.salt = os.urandom(32)
    #     user_model.password = self.make_hash_password(password, user_model.salt)
    #     return user_model

    def compare_password(self, current_password: str, salt: bytes, compare_password: str) -> bool:
        return True if self.make_hash_password(compare_password, salt) == current_password else False

password = Password()