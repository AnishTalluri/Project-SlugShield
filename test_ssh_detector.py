# test_ssh_detector.py
import time
import pytest
from scapy.layers.inet import IP, TCP
from ids_backend.ssh_detector import ssh_detector, _recent_attempts, _alerted_srcs, _last_stat_time

# -----------------------------------
# Dummy broadcaster for test isolation
# -----------------------------------
class DummyBroadcaster:
    def __init__(self):
        self.alerts = []
        self.stats = []

    async def push_alert(self, alert_data):
        self.alerts.append(alert_data)

    def push_stat(self, stat_data):
        self.stats.append(stat_data)

# Replace real broadcaster with dummy
import ids_backend.ssh_detector as detector_module
detector_module.broadcaster = DummyBroadcaster()


# -----------------------------------
# Packet Factory Helper
# -----------------------------------
def make_ssh_packet(src_ip="192.168.1.55", dport=22, syn=True):
    """Generate a Scapy SSH-like packet."""
    flags = "S" if syn else ""
    return IP(src=src_ip) / TCP(dport=dport, flags=flags)


# -----------------------------------
# Test Cases
# -----------------------------------
def test_no_alert_under_threshold():
    """Ensure detector does not alert for fewer than threshold attempts."""
    _recent_attempts.clear()
    _alerted_srcs.clear()
    detector_module.broadcaster.alerts.clear()
    for _ in range(5):  # below threshold of 10
        ssh_detector(make_ssh_packet())
    assert len(detector_module.broadcaster.alerts) == 0


def test_alert_triggered_at_threshold(monkeypatch):
    """Ensure alert is generated when attempts exceed threshold."""
    _recent_attempts.clear()
    _alerted_srcs.clear()
    detector_module.broadcaster.alerts.clear()

    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)

    for _ in range(12):
        ssh_detector(make_ssh_packet())

    # Wait for async task to finish if running
    time.sleep(0.1)

    assert len(detector_module.broadcaster.alerts) == 1
    alert = detector_module.broadcaster.alerts[0]
    assert alert["detector"] == "ssh_bruteforce"
    assert "Repeated SSH login attempts" in alert["message"]


def test_ignores_non_syn_packets():
    """Ensure packets without SYN flag are ignored."""
    _recent_attempts.clear()
    _alerted_srcs.clear()
    detector_module.broadcaster.alerts.clear()

    pkt = make_ssh_packet(syn=False)
    ssh_detector(pkt)

    assert len(detector_module.broadcaster.alerts) == 0


def test_ignores_non_ssh_port():
    """Ensure packets not targeting port 22 are ignored."""
    _recent_attempts.clear()
    _alerted_srcs.clear()
    detector_module.broadcaster.alerts.clear()

    pkt = make_ssh_packet(dport=80)
    ssh_detector(pkt)

    assert len(detector_module.broadcaster.alerts) == 0


def test_pushes_ssh_stats(monkeypatch):
    """Ensure ssh_detector pushes ssh_attempts_per_second stats roughly once per second."""
    _recent_attempts.clear()
    _alerted_srcs.clear()
    detector_module.broadcaster.stats.clear()

    # simulate multiple SSH packets over 2 seconds
    start_time = time.time()
    fake_time = [start_time]

    def fake_time_fn():
        return fake_time[0]

    monkeypatch.setattr(time, "time", fake_time_fn)
    detector_module._last_stat_time = 0  # reset stat timer

    # send first batch of packets
    for _ in range(5):
        ssh_detector(make_ssh_packet())

    # simulate one second later
    fake_time[0] += 1.1
    for _ in range(3):
        ssh_detector(make_ssh_packet())

    # we should have at least one stat entry
    assert len(detector_module.broadcaster.stats) >= 1
    stat = detector_module.broadcaster.stats[-1]
    assert stat["metric"] == "ssh_attempts_per_second"
    assert "value" in stat and isinstance(stat["value"], float)
    assert stat["value"] >= 0
