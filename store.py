import random
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from threading import Lock
from collections import namedtuple

StorageResult = namedtuple('StorageResult', ('good', 'data'))


class DistantStorage:
    """имитация удаленного хранилища со случайными задержками ответа и случайными отказами соединения"""
    def __init__(self):
        self.storage = {}

    def get(self, key):
        if random.randint(0, 1) == 1:
            time.sleep(random.random())
            return StorageResult(True, self.storage.get(key))
        else:
            time.sleep(random.random())
            return StorageResult(False, None)

    def set(self, key, value):
        if random.randint(0, 1) == 1:
            self.storage[key] = value
            time.sleep(random.random())
            return True
        else:
            time.sleep(random.random())
            return False


class Store:
    def __init__(self, max_attempts=10, max_timeout=1, max_workers=3):
        self.__cache = {}
        self.__mutex = Lock()
        self.__storage = DistantStorage()
        self.__attempts = max_attempts
        self.__timeout = max_timeout
        self.__thread_pool = ThreadPoolExecutor(max_workers=max_workers)
        self.__event_loop = asyncio.get_event_loop()
        self.__event_loop.run_in_executor(self.__thread_pool)

    def stop(self):
        self.__event_loop.stop()

    async def __remove_entry(self, key, duration):
        await asyncio.sleep(duration)
        with self.__mutex:
            self.__cache.pop(key)

    def __update_cache(self, key, value, store_duration_sec):
        with self.__mutex:
            self.__cache[key] = value

        self.__event_loop.create_task(self.__remove_entry(key, store_duration_sec))

    def __read_cache(self, key):
        with self.__mutex:
            if key in self.__cache:
                return StorageResult(True, self.__cache[key])
            else:
                return StorageResult(False, None)

    def cache_get(self, key):
        result = self.__read_cache(key)
        if result.good:
            return result.data

    def cache_set(self, key, value, store_duration_sec):
        self.__update_cache(key, value, store_duration_sec)

    def get(self, key):
        for att in range(self.__attempts):
            future = self.__thread_pool.submit(self.__storage.get, key)
            try:
                get_result = future.result(timeout=self.__timeout)
            except TimeoutError:
                continue

            if get_result.good:
                return get_result.data

    def set(self, key, value):
        for att in range(self.__attempts):
            future = self.__thread_pool.submit(self.__storage.set, key, value)
            try:
                set_result = future.result(timeout=self.__timeout)
            except TimeoutError:
                continue

            if set_result:
                return
