import time
from dataclasses import dataclass
from typing import Dict, List, Tuple

import pandas as pd
from scapy.all import IP, TCP, UDP, sniff

from mitigation.detection.inference_adapter import InferenceAdapter


FLOW_TIMEOUT = 5.0
WINDOW_SIZE = 100

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
    def _canonical_key(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
    ):
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

        (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        ) = info

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


# ============================================================
# LIVE DETECTION INTEGRATION
# ============================================================

class LiveDetectionPipeline:
    """
    Buffers completed flow records into 100-flow windows
    and sends each window through the existing frozen
    InferenceAdapter.
    """

    def __init__(self):
        self.inference = InferenceAdapter()
        self.flow_buffer: List[Dict[str, float]] = []

    def add_flow(self, flow: Flow):
        features = flow.to_features()

        self.flow_buffer.append(features)

        print(
            f"\nCompleted flow added to detection buffer: "
            f"{len(self.flow_buffer)}/{WINDOW_SIZE}"
        )

        if len(self.flow_buffer) >= WINDOW_SIZE:
            self.run_inference()

    def run_inference(self):
        window = self.flow_buffer[:WINDOW_SIZE]

        self.flow_buffer = self.flow_buffer[WINDOW_SIZE:]

        flow_window = pd.DataFrame(
            window,
            columns=STAT_FEATURES,
        )

        print("\n" + "=" * 70)
        print("LIVE DETECTION WINDOW READY")
        print("=" * 70)

        try:
            result = self.inference.predict_window(
                flow_window
            )

            print("\nLIVE INFERENCE RESULT")
            print("-" * 70)
            print(result)

        except Exception as exc:
            print("\nLIVE INFERENCE ERROR")
            print("-" * 70)
            print(f"{type(exc).__name__}: {exc}")


def handle_completed_flow(flow):
    print("\nCOMPLETED FLOW")
    print("-" * 60)
    print(flow.to_features())

    detection_pipeline.add_flow(flow)


def packet_handler(packet):
    timestamp = float(packet.time)

    collector.process_packet(
        packet,
        timestamp=timestamp,
    )

    expired = collector.expire_flows(timestamp)

    for completed_flow in expired:
        handle_completed_flow(completed_flow)


def main():
    global collector
    global detection_pipeline

    collector = FlowCollector()
    detection_pipeline = LiveDetectionPipeline()

    print("=" * 70)
    print("STEALTHGUARD LIVE FLOW COLLECTOR")
    print("=" * 70)

    print("\nInterface: cp-gateway eth1")
    print("Capturing client-side traffic...")
    print("100 completed flows -> frozen ML inference")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
        sniff(
            iface="eth1",
            prn=packet_handler,
            store=False,
            timeout=1,
        )

    except PermissionError:
        print("\nERROR: Packet capture requires root privileges.")
        print("Run the collector with sudo.")

    except KeyboardInterrupt:
        print("\n\nStopping capture...")

        completed = collector.flush()

        for flow in completed:
            handle_completed_flow(flow)


if __name__ == "__main__":
    main()