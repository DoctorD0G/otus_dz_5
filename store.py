import redis
import time
from redis.exceptions import RedisError


class KeyValueStore:
    def __init__(self, host='localhost', port=6379, db=0, retries=5, timeout=5):
        self.host = host
        self.port = port
        self.db = db
        self.retries = retries
        self.timeout = timeout
        self.connection = self.connect()

    def connect(self):
        for attempt in range(self.retries):
            try:
                connection = redis.StrictRedis(
                    host=self.host,
                    port=self.port,
                    db=self.db,
                    socket_connect_timeout=self.timeout,
                    socket_timeout=self.timeout,
                    decode_responses=True
                )
                connection.ping()  # Проверка подключения
                return connection
            except RedisError:
                time.sleep(2)  # Задержка перед повторной попыткой
        raise ConnectionError("Could not connect to Redis after multiple attempts.")

    def get(self, key):
        try:
            return self.connection.get(key)
        except RedisError:
            self.connection = self.connect()  # Переподключение при ошибке
            return self.get(key)  # Повторный запрос

    def cache_get(self, key):
        return self.get(key)

    def cache_set(self, key, value, expire):
        try:
            self.connection.setex(key, expire, value)
        except RedisError:
            self.connection = self.connect()  # Переподключение при ошибке
            self.cache_set(key, value, expire)  # Повторный запрос
