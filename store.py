class Store:
    def __init__(self, storage_instance, max_attempts=10, max_timeout=1):
        self.__cache = {}
        self.__storage = storage_instance
        self.__attempts = max_attempts
        self.__timeout = max_timeout

    def cache_get(self, key):
        return self.__storage.get(key)

    def cache_set(self, key, value, store_duration_sec):
        self.__storage.set(key, value, ex=store_duration_sec)

    def get(self, key):
        return self.__storage.get(key)

    def set(self, key, value):
        self.__storage.set(key, value)
