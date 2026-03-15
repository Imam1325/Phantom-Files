"""Тесты rate-limiter (token bucket)."""

import time

from phantom.api.asgi_app import _TokenBucket


# ---------- начальное состояние ----------

def test_bucket_initial_full():
    bucket = _TokenBucket(capacity=10, rate=1.0)
    for _ in range(10):
        assert bucket.consume() is True
    assert bucket.consume() is False


def test_bucket_initial_capacity_one():
    bucket = _TokenBucket(capacity=1, rate=0.0)
    assert bucket.consume() is True
    assert bucket.consume() is False


# ---------- пополнение ----------

def test_bucket_refill():
    bucket = _TokenBucket(capacity=2, rate=100.0)
    bucket.consume()
    bucket.consume()
    assert bucket.consume() is False
    time.sleep(0.05)
    assert bucket.consume() is True


def test_bucket_capacity_limit():
    bucket = _TokenBucket(capacity=3, rate=1000.0)
    time.sleep(0.01)
    for _ in range(3):
        assert bucket.consume() is True
    assert bucket.consume() is False


def test_bucket_zero_rate():
    bucket = _TokenBucket(capacity=1, rate=0.0)
    assert bucket.consume() is True
    assert bucket.consume() is False
    time.sleep(0.1)
    assert bucket.consume() is False


def test_bucket_refill_does_not_exceed_capacity():
    """После большого sleep не должно быть больше capacity токенов."""
    bucket = _TokenBucket(capacity=5, rate=100.0)
    # Полностью опустошаем
    for _ in range(5):
        bucket.consume()
    time.sleep(0.2)  # 20 токенов при rate=100, но capacity=5
    consumed = 0
    for _ in range(10):
        if bucket.consume():
            consumed += 1
    assert consumed == 5


# ---------- consume multiple ----------

def test_bucket_rapid_consume():
    """Быстрое consume без пауз."""
    bucket = _TokenBucket(capacity=100, rate=0.0)
    consumed = sum(1 for _ in range(200) if bucket.consume())
    assert consumed == 100


# ---------- edge cases ----------

def test_bucket_large_capacity():
    bucket = _TokenBucket(capacity=10000, rate=0.0)
    for _ in range(10000):
        assert bucket.consume() is True
    assert bucket.consume() is False


def test_bucket_fractional_refill():
    """Дробные токены аккумулируются корректно."""
    bucket = _TokenBucket(capacity=10, rate=10.0)  # 10 tok/s
    for _ in range(10):
        bucket.consume()
    time.sleep(0.15)  # ~1.5 токена
    assert bucket.consume() is True  # 1-й
    # 2-й может не быть (зависит от точности таймера)
