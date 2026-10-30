import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Tuple

from scapy.all import IP, TCP, UDP, sniff


FLOW_TIMEOUT = 5.0

STAT_FEATURES = [
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Average Packet Size",
]


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    start_time: float
    last_time: float

    forward_packets: int = 0
    backward_packets: int = 0

    forward_bytes: int = 0
    backward_bytes: int = 0

    packet_lengths: List[int] = None

    def __post_init__(self):
        if self.packet_lengths is None:
            self.packet_lengths = []

    @property
    def total_packets(self):
        return self.forward_packets + self.backward_packets

    @property
    def total_bytes(self):
        return self.forward_bytes + self.backward_bytes

    @property
    def duration(self):
        return max(self.last_time - self.start_time, 0.000001)

    def add_packet(self, packet, timestamp):
        packet_length = len(packet)

        self.last_time = timestamp
        self.packet_lengths.append(packet_length)

        packet_src = packet[IP].src
        packet_dst = packet[IP].dst

        if packet_src == self.src_ip and packet_dst == self.dst_ip:
            self.forward_packets += 1
            self.forward_bytes += packet_length
        else:
            self.backward_packets += 1
            self.backward_bytes += packet_length

    def to_features(self) -> Dict[str, float]:
        packet_count = self.total_packets
        total_bytes = self.total_bytes

        if packet_count > 0:
            mean_packet_length = (
                sum(self.packet_lengths) / packet_count
            )
        else:
            mean_packet_length = 0.0

        if packet_count > 1:
            mean = mean_packet_length
            variance = sum(
                (length - mean) ** 2
                for length in self.packet_lengths
            ) / packet_count

            packet_length_std = variance ** 0.5
        else:
            packet_length_std = 0.0

        return {
            "Flow Duration": self.duration,
            "Flow Bytes/s": total_bytes / self.duration,
            "Flow Packets/s": packet_count / self.duration,
            "Packet Length Mean": mean_packet_length,
            "Packet Length Std": packet_length_std,
            "Total Fwd Packets": self.forward_packets,
            "Total Backward Packets": self.backward_packets,
            "Average Packet Size": (
                total_bytes / packet_count
                if packet_count > 0
                else 0.0
            ),
        }


class FlowCollector:
    """
    Converts captured packets into bidirectional flow records.

    Flow key:
        source IP
        destination IP
        source port
        destination port
        protocol

    Reverse traffic is associated with the same flow.
    """

    def __init__(self, flow_timeout: float = FLOW_TIMEOUT):
        self.flow_timeout = flow_timeout
        self.flows: Dict[Tuple, Flow] = {}

    @staticmethod
    def _packet_info(packet):
        if IP not in packet:
            return None

        ip = packet[IP]

        if TCP in packet:
            protocol = 6
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif UDP in packet:
            protocol = 17
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        else:
            return None

        return (
            ip.src,
            ip.dst,
            int(src_port),
            int(dst_port),
            protocol,
        )

    @staticmethod
    def _canonical_key(src_ip, dst_ip, src_port, dst_port, protocol):
        forward = (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        )

        reverse = (
            dst_ip,
            src_ip,
            dst_port,
            src_port,
            protocol,
        )

        return forward, reverse

    def process_packet(self, packet, timestamp=None):
        if timestamp is None:
            timestamp = time.time()

        info = self._packet_info(packet)

        if info is None:
            return None

        src_ip, dst_ip, src_port, dst_port, protocol = info

        forward_key, reverse_key = self._canonical_key(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        )

        if forward_key in self.flows:
            flow_key = forward_key

        elif reverse_key in self.flows:
            flow_key = reverse_key

        else:
            flow_key = forward_key

            self.flows[flow_key] = Flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                start_time=timestamp,
                last_time=timestamp,
            )

        flow = self.flows[flow_key]

        flow.add_packet(packet, timestamp)

        return flow

    def expire_flows(self, current_time=None):
        if current_time is None:
            current_time = time.time()

        completed = []

        for key, flow in list(self.flows.items()):
            if current_time - flow.last_time >= self.flow_timeout:
                completed.append(flow)
                del self.flows[key]

        return completed

    def flush(self):
        completed = list(self.flows.values())
        self.flows.clear()
        return completed


def packet_handler(packet):
    """
    Simple standalone handler used by the live capture test.
    """

    timestamp = float(packet.time)

    flow = collector.process_packet(
        packet,
        timestamp=timestamp,
    )

    expired = collector.expire_flows(timestamp)

    for completed_flow in expired:
        print("\nCOMPLETED FLOW")
        print("-" * 60)
        print(completed_flow.to_features())


def main():
    global collector

    collector = FlowCollector()

    print("=" * 70)
    print("STEALTHGUARD LIVE FLOW COLLECTOR")
    print("=" * 70)

    print("\nInterface: cp-gateway eth1")
    print("Capturing client-side traffic...")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface="eth1",
            prn=packet_handler,
            store=False,
        )

    except PermissionError:
        print("\nERROR: Packet capture requires root privileges.")
        print("Run the collector with sudo.")

    except KeyboardInterrupt:
        print("\n\nStopping capture...")

        completed = collector.flush()

        for flow in completed:
            print("\nFINAL FLOW")
            print("-" * 60)
            print(flow.to_features())


if __name__ == "__main__":
    main()