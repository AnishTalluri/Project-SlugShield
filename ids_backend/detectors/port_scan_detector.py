"""
Port Scan Detector

This detector flags hosts that probe many ports/hosts in a short period, or that
send lots of SYNs without completing TCP handshakes (classic SYN scan). It also
optionally watches for UDP scans (many UDP probes causing ICMP Port Unreachable).

Design overview (short version):

- Maintain fast-window statistics (e.g., 60–120s) using timestamp deques:
  - Count SYNs, SYN-ACKs, UDP probes, ICMP Port Unreachables.
  - Track UNIQUE destination ports per (src_ip -> dst_ip).
  - Track UNIQUE destination hosts per src_ip.

- Maintain slow-window statistics using decayed counters over a larger horizon
  (e.g., 10–30 minutes). This gives “background” behaviour without storing
  every packet.

- Compute the following for each source IP:
  - syn_fast, synack_fast, udp_fast
  - unique_ports_fast, unique_hosts_fast
  - syn_to_synack ratio
  - syn_slow, synack_slow, udp_slow, icmp_slow
  - syn_ratio_slow, udp_icmp_ratio

- Raise an alert if any heuristic rule is triggered, e.g.:
  - FAST_TCP: many unique ports probed in the fast window AND a high SYN:SYN-ACK ratio.
  - FAST_HOST_SWEEP: many distinct destination hosts and bad handshake ratio.
  - SLOW_TCP: many unique ports over the slow window and bad ratio.
  - UDP_SCAN: many UDP probes with a large fraction resulting in ICMP Port Unreachable.

This module is intentionally self-contained and synchronous. The centralized_detector
base class wires self.alert(...) to the alert_manager, which can in turn forward
alerts to the async WebSocket broadcaster when an event loop is present.
"""

import time
import ipaddress
from collections import defaultdict, deque

from scapy.layers.inet import IP, TCP, UDP, ICMP

from ..centralized_detector import centralized_detector


class port_scan_detector(centralized_detector):
    """
    Stateful port scan detector.

    All thresholds are provided by app_config (usually from config.yaml):

    - portscan_fast_window_seconds
    - portscan_slow_window_seconds
    - portscan_slow_decay
    - portscan_min_unique_ports_fast
    - portscan_min_unique_ports_slow
    - portscan_min_unique_hosts_fast
    - portscan_min_syns_fast
    - portscan_max_syn_to_synack
    - portscan_enable_udp_detection
    - portscan_min_udp_probes_fast
    - portscan_min_icmp_ratio
    - portscan_whitelist_cidrs
    """

    def __init__(self, app_config, alert_manager):
        super().__init__(app_config, alert_manager)

        # --- Config (tuned via config.yaml) ---
        self.fast_window_s = app_config.portscan_fast_window_seconds
        self.slow_window_s = app_config.portscan_slow_window_seconds
        self.decay_factor = app_config.portscan_slow_decay

        self.min_ports_fast = app_config.portscan_min_unique_ports_fast
        self.min_ports_slow = app_config.portscan_min_unique_ports_slow
        self.min_hosts_fast = app_config.portscan_min_unique_hosts_fast
        self.min_syns_fast = app_config.portscan_min_syns_fast
        self.max_syn_ack_ratio = app_config.portscan_max_syn_to_synack

        self.enable_udp = app_config.portscan_enable_udp_detection
        self.min_udp_probes = app_config.portscan_min_udp_probes_fast
        self.min_icmp_unreach_ratio = app_config.portscan_min_icmp_ratio

        self.whitelist_cidrs = app_config.portscan_whitelist_cidrs or []

        # Optional debug flag (not required in config)
        self.debug = getattr(app_config, "portscan_debug", False)

        # Precompute whitelist networks
        self._whitelist_networks = []
        for cidr in self.whitelist_cidrs:
            try:
                self._whitelist_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                # Allow exact IPs or malformed entries to be ignored gracefully
                try:
                    self._whitelist_networks.append(
                        ipaddress.ip_network(cidr + "/32", strict=False)
                    )
                except Exception:
                    # Final fallback: ignore bad entry
                    pass

        # --- Data structures (per source IP) ---

        # Sliding-window event logs (timestamps only) for fast-window calculations
        self.events = defaultdict(
            lambda: {
                "syn_times": deque(),
                "synack_times": deque(),
                "rst_times": deque(),
                "udp_times": deque(),
                "icmp_unreach_times": deque(),
            }
        )

        # Fast-window uniqueness tracking:
        #   src_ip -> dst_ip -> {dst_port}
        self.unique_ports_fast = defaultdict(lambda: defaultdict(set))
        #   src_ip -> {dst_ip}
        self.unique_hosts_fast = defaultdict(set)

        # Slow-window counts (decayed):
        # Note: we track unique ports/hosts as sets, plus decayed counters.
        self.slow_counts = defaultdict(
            lambda: {
                "unique_ports": defaultdict(set),  # dst_ip -> {dst_port}
                "unique_hosts": set(),
                "syn": 0.0,
                "synack": 0.0,
                "udp": 0.0,
                "icmp_unreach": 0.0,
            }
        )

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def is_whitelisted(self, ip_str: str) -> bool:
        """Return True if the source IP is in any whitelist CIDR."""
        if not self._whitelist_networks:
            return False

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            # If it's not a valid IP string, don't treat it as whitelisted.
            return False

        for net in self._whitelist_networks:
            if ip_obj in net:
                if self.debug:
                    print(f"[PORTSCAN][DEBUG] {ip_str} is whitelisted by {net}")
                return True

        return False

    @staticmethod
    def _prune_times(dq: deque, window_s: float, now: float) -> None:
        """Drop timestamps older than window_s from the left of the deque."""
        while dq and (now - dq[0]) > window_s:
            dq.popleft()

    def _prune_fast_uniques(self, src_ip: str, now: float) -> None:
        """
        Approximate pruning for fast-window uniqueness sets.

        We don't keep per-(port, timestamp) history here, so we can't do a perfect
        time-based prune. For the purposes of this class (especially small demos
        and tests), it's acceptable to leave these sets growing over the life of
        the process.

        This method is kept as a hook in case we later decide to maintain a short
        per-source cache of recent packets and rebuild the sets exactly.
        """
        return

    def _apply_slow_decay(self, src_ip: str) -> None:
        """
        Apply exponential decay to slow-window counters for this src_ip.

        This is called opportunistically on every packet from src_ip. For small
        demo loads, this is fine; for very high traffic rates you might prefer
        to track last_decay_time and scale by elapsed time instead.
        """
        sc = self.slow_counts[src_ip]
        sc["syn"] *= self.decay_factor
        sc["synack"] *= self.decay_factor
        sc["udp"] *= self.decay_factor
        sc["icmp_unreach"] *= self.decay_factor
        # We intentionally leave the unique_* sets untouched; they approximate
        # slow-window uniqueness over the lifetime of the process.

    # ------------------------------------------------------------------
    # Main entry point from PacketCapture
    # ------------------------------------------------------------------

    def analyze_packet(self, packet):
        """Called by PacketCapture for every Scapy packet."""
        # Only proceed if there is an IP layer.
        if IP not in packet:
            return

        now = time.time()
        ip_layer = packet.getlayer(IP)
        src = ip_layer.src
        dst = ip_layer.dst

        if self.is_whitelisted(src):
            return

        # Apply slow-decay to this source on each packet.
        self._apply_slow_decay(src)

        # TCP handling (SYN / SYN+ACK / RST)
        if TCP in packet:
            tcp = packet.getlayer(TCP)
            sport, dport = tcp.sport, tcp.dport
            flags = int(tcp.flags)

            if self.debug:
                print(
                    f"[PORTSCAN][DEBUG][TCP] {src}:{sport} -> {dst}:{dport} | "
                    f"flags=0x{flags:02x} (SYN={bool(flags & 0x02)}, "
                    f"ACK={bool(flags & 0x10)}, RST={bool(flags & 0x04)})"
                )

            # Outbound SYN from src -> dst (SYN set, ACK not set)
            if (flags & 0x02) and not (flags & 0x10):
                self.events[src]["syn_times"].append(now)
                self.unique_ports_fast[src][dst].add(dport)
                self.unique_hosts_fast[src].add(dst)

                sc = self.slow_counts[src]
                sc["unique_ports"][dst].add(dport)
                sc["unique_hosts"].add(dst)
                sc["syn"] += 1.0

                if self.debug:
                    print(
                        f"[PORTSCAN][DEBUG] SYN from {src} -> {dst}:{dport} "
                        f"(unique_ports_fast={sum(len(p) for p in self.unique_ports_fast[src].values())}, "
                        f"unique_hosts_fast={len(self.unique_hosts_fast[src])})"
                    )

            # Also track any outbound TCP attempt to a port as a potential probe
            # Check if this packet is going OUT from src (src_ip == local initiator)
            # If we see multiple different destination ports, it's likely a scan
            if (flags & 0x02) or (flags & 0x04) or (flags & 0x01) or (flags & 0x10):
                # Track port probes on outbound connections
                self.unique_ports_fast[src][dst].add(dport)
                self.unique_hosts_fast[src].add(dst)

                sc = self.slow_counts[src]
                sc["unique_ports"][dst].add(dport)
                sc["unique_hosts"].add(dst)

            # Inbound SYN+ACK (flags 0x12) returning to the initiator
            if (flags & 0x12) == 0x12:
                # The initiator is the destination of this packet
                initiator = ip_layer.dst
                self.events[initiator]["synack_times"].append(now)
                self.slow_counts[initiator]["synack"] += 1.0

                if self.debug:
                    print(
                        f"[PORTSCAN][DEBUG] SYN-ACK to {initiator} from "
                        f"{ip_layer.src}:{sport}"
                    )

            # Track RSTs (handy for possible future heuristics, but not used directly)
            if flags & 0x04:
                self.events[src]["rst_times"].append(now)

        # UDP probes (if enabled)
        if self.enable_udp and UDP in packet:
            udp = packet.getlayer(UDP)
            self.events[src]["udp_times"].append(now)
            self.unique_ports_fast[src][dst].add(udp.dport)
            self.unique_hosts_fast[src].add(dst)

            sc = self.slow_counts[src]
            sc["unique_ports"][dst].add(udp.dport)
            sc["unique_hosts"].add(dst)
            sc["udp"] += 1.0

        # ICMP Port Unreachable indicates a closed UDP port on the probed host.
        if self.enable_udp and ICMP in packet:
            icmp = packet.getlayer(ICMP)
            # Type 3, Code 3 = Destination Unreachable: Port Unreachable
            if getattr(icmp, "type", None) == 3 and getattr(icmp, "code", None) == 3:
                # Attribute to original UDP initiator; in a real system you'd track
                # the embedded IP/UDP header to find it. For now, treat ip_layer.dst
                # as the initiator.
                initiator = ip_layer.dst
                self.events[initiator]["icmp_unreach_times"].append(now)
                self.slow_counts[initiator]["icmp_unreach"] += 1.0

        # ------------------------------------------------------------------
        # Prune fast-window timestamp deques
        # ------------------------------------------------------------------
        ev = self.events[src]
        self._prune_times(ev["syn_times"], self.fast_window_s, now)
        self._prune_times(ev["synack_times"], self.fast_window_s, now)
        self._prune_times(ev["rst_times"], self.fast_window_s, now)
        if self.enable_udp:
            self._prune_times(ev["udp_times"], self.fast_window_s, now)
            self._prune_times(ev["icmp_unreach_times"], self.fast_window_s, now)

        # Approximate prune for uniqueness sets (currently a no-op)
        self._prune_fast_uniques(src, now)

        # ------------------------------------------------------------------
        # Compute fast-window metrics
        # ------------------------------------------------------------------
        syn_fast = len(ev["syn_times"])
        synack_fast = len(ev["synack_times"])
        udp_fast = len(ev["udp_times"]) if self.enable_udp else 0

        unique_ports_fast = sum(len(ports) for ports in self.unique_ports_fast[src].values())
        unique_hosts_fast = len(self.unique_hosts_fast[src])

        syn_to_synack = (syn_fast / max(1, synack_fast)) if syn_fast > 0 else 0.0

        # ------------------------------------------------------------------
        # Compute slow-window (decayed) metrics
        # ------------------------------------------------------------------
        sc = self.slow_counts[src]
        unique_ports_slow = sum(len(ports) for ports in sc["unique_ports"].values())
        unique_hosts_slow = len(sc["unique_hosts"])
        syn_slow = sc["syn"]
        synack_slow = sc["synack"]
        udp_slow = sc["udp"]
        icmp_slow = sc["icmp_unreach"]

        syn_ratio_slow = (syn_slow / max(1.0, synack_slow)) if syn_slow > 0 else 0.0
        udp_icmp_ratio = (icmp_slow / max(1.0, udp_slow)) if udp_slow > 0 else 0.0

        if self.debug:
            print(
                "[PORTSCAN][DEBUG][METRICS] "
                f"src={src} | "
                f"syn_fast={syn_fast}, synack_fast={synack_fast}, "
                f"unique_ports_fast={unique_ports_fast}, unique_hosts_fast={unique_hosts_fast}, "
                f"syn_to_synack={syn_to_synack:.2f}, "
                f"udp_fast={udp_fast}, udp_slow={udp_slow:.1f}, icmp_slow={icmp_slow:.1f}, "
                f"udp_icmp_ratio={udp_icmp_ratio:.2f}"
            )

        # ------------------------------------------------------------------
        # Heuristic rules
        # ------------------------------------------------------------------
        reasons = []

        # FAST_TCP: many unique ports + poor handshake completion
        if unique_ports_fast >= self.min_ports_fast and syn_to_synack >= self.max_syn_ack_ratio:
            reasons.append(
                f"FAST_TCP: {unique_ports_fast} unique ports, "
                f"SYN:SYN-ACK={syn_to_synack:.1f}"
            )

        # FAST_TCP_PROBING: many unique ports regardless of handshake (simpler heuristic)
        if unique_ports_fast >= self.min_ports_fast and syn_fast >= self.min_syns_fast:
            reasons.append(
                f"FAST_TCP_PROBING: {unique_ports_fast} unique ports, "
                f"SYNs={syn_fast}"
            )

        # FAST_HOST_SWEEP: many hosts, enough SYNs, and bad handshake ratio
        if (
            unique_hosts_fast >= self.min_hosts_fast
            and syn_fast >= self.min_syns_fast
            and syn_to_synack >= self.max_syn_ack_ratio
        ):
            reasons.append(
                f"FAST_HOST_SWEEP: {unique_hosts_fast} unique hosts, "
                f"SYNs={syn_fast}, SYN:SYN-ACK={syn_to_synack:.1f}"
            )

        # SLOW_TCP: many unique ports over slow window + bad ratio
        if unique_ports_slow >= self.min_ports_slow and syn_ratio_slow >= self.max_syn_ack_ratio:
            reasons.append(
                f"SLOW_TCP: {unique_ports_slow} unique ports (slow window), "
                f"SYN:SYN-ACK={syn_ratio_slow:.1f}"
            )

        # UDP_SCAN: many UDP probes AND high ICMP-unreachable ratio
        if (
            self.enable_udp
            and udp_fast >= self.min_udp_probes
            and udp_icmp_ratio >= self.min_icmp_unreach_ratio
        ):
            reasons.append(
                f"UDP_SCAN: udp_fast={udp_fast}, udp_slow={udp_slow:.1f}, "
                f"icmp_slow={icmp_slow:.1f}, udp_icmp_ratio={udp_icmp_ratio:.2f}"
            )

        # If any heuristic fired, emit an alert.
        if reasons:
            alert = {
                "timestamp": now,
                "detector": "port_scan",
                "src": src,
                "severity": "medium",
                "fast_metrics": {
                    "unique_ports": unique_ports_fast,
                    "unique_hosts": unique_hosts_fast,
                    "syn": syn_fast,
                    "synack": synack_fast,
                    "syn_to_synack": round(syn_to_synack, 2),
                    "udp": udp_fast,
                },
                "slow_metrics": {
                    "unique_ports": unique_ports_slow,
                    "unique_hosts": unique_hosts_slow,
                    "syn": round(syn_slow, 1),
                    "synack": round(synack_slow, 1),
                    "syn_to_synack": round(syn_ratio_slow, 2),
                    "udp": round(udp_slow, 1),
                    "icmp_unreach": round(icmp_slow, 1),
                    "udp_icmp_ratio": round(udp_icmp_ratio, 2)
                    if self.enable_udp
                    else None,
                },
                "message": (
                    f"Port scan suspected from {src}. "
                    f"Fast uniques: ports={unique_ports_fast}, hosts={unique_hosts_fast}; "
                    f"Slow uniques: ports={unique_ports_slow}, hosts={unique_hosts_slow}. "
                    f"Reasons: {', '.join(reasons)}"
                ),
            }

            # Debug-only 
            if self.debug:
                print(f"[PORTSCAN][DEBUG][ALERT] {alert['message']}")

            # Always print the simple alert line for the harness / logs
            print(f"ALERT: Port scan detected from {src}")

            # centralized_detector wires self.alert to alert_manager.push_alert(...)
            self.alert(alert)

