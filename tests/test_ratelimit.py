import os

import pytest

from vaptframework.core.ratelimit import TokenBucket, KillSwitch, Throttle, TestingHalted


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def monotonic(self):
        return self.t

    def sleep(self, secs):
        self.t += secs


def test_bucket_allows_burst_then_blocks():
    clk = FakeClock()
    b = TokenBucket(rate_per_sec=2, burst=2, _clock=clk.monotonic, _sleep=clk.sleep)
    assert b.try_acquire() is True
    assert b.try_acquire() is True
    assert b.try_acquire() is False  # burst exhausted, no time passed


def test_bucket_refills_over_time():
    clk = FakeClock()
    b = TokenBucket(rate_per_sec=10, burst=1, _clock=clk.monotonic, _sleep=clk.sleep)
    assert b.try_acquire() is True
    assert b.try_acquire() is False
    clk.t += 0.1  # 0.1s * 10/s = 1 token
    assert b.try_acquire() is True


def test_acquire_blocks_and_reports_wait():
    clk = FakeClock()
    b = TokenBucket(rate_per_sec=1, burst=1, _clock=clk.monotonic, _sleep=clk.sleep)
    assert b.acquire() == 0.0            # first token free
    waited = b.acquire()                  # must wait ~1s
    assert waited == pytest.approx(1.0, abs=1e-6)


def test_invalid_rate():
    with pytest.raises(ValueError):
        TokenBucket(rate_per_sec=0)


def test_kill_switch(tmp_path):
    stop = os.path.join(tmp_path, "STOP")
    ks = KillSwitch(stop_file=stop)
    assert ks.engaged() is False
    ks.check()  # no raise
    ks.engage("stop now")
    assert ks.engaged() is True
    with pytest.raises(TestingHalted):
        ks.check()
    ks.clear()
    assert ks.engaged() is False


def test_throttle_gate_respects_kill_switch(tmp_path):
    stop = os.path.join(tmp_path, "STOP")
    ks = KillSwitch(stop_file=stop)
    clk = FakeClock()
    thr = Throttle(TokenBucket(5, 5, _clock=clk.monotonic, _sleep=clk.sleep), ks)
    thr.gate()  # fine
    ks.engage()
    with pytest.raises(TestingHalted):
        thr.gate()
