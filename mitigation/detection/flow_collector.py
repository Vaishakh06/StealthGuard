import signal
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
        if TCP in packet:
            packet_length = len(packet[TCP].payload)
        elif UDP in packet:
            packet_length = len(packet[UDP].payload)
        else:
            raise ValueError("Flow packets must contain TCP or UDP")

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
            # CICFlowMeter records the first packet twice in flowLengthStats.
            first_packet_length = self.packet_lengths[0]
            flow_length_sum = total_bytes + first_packet_length
            flow_length_count = packet_count + 1
            mean_packet_length = flow_length_sum / flow_length_count

            squared_deviations = sum(
                (length - mean_packet_length) ** 2
                for length in self.packet_lengths
            ) + (first_packet_length - mean_packet_length) ** 2
            packet_length_std = (
                squared_deviations / packet_count
            ) ** 0.5
            average_packet_size = flow_length_sum / packet_count
        else:
            mean_packet_length = 0.0
            packet_length_std = 0.0
            average_packet_size = 0.0

        return {
            "Flow Duration": self.duration * 1_000_000,
            "Flow Bytes/s": total_bytes / self.duration,
            "Flow Packets/s": packet_count / self.duration,
            "Packet Length Mean": mean_packet_length,
            "Packet Length Std": packet_length_std,
            "Total Fwd Packets": self.forward_packets,
            "Total Backward Packets": self.backward_packets,
            "Average Packet Size": average_packet_size,
        }


class FlowCollector:
    """
    Converts captured packets into bidirectional flow records.
    """

    def __init__(self, flow_timeout: float = FLOW_TIMEOUT):
        self.flow_timeout = flow_timeout
        self.flows: Dict[Tuple, Flow] = {}
        self.diagnostics = {
            "packets_captured": 0,
            "tcp_syn_packets": 0,
            "tcp_syn_ack_packets": 0,
            "tcp_ack_packets": 0,
            "tcp_fin_packets": 0,
            "tcp_rst_packets": 0,
            "client_to_server_tcp_packets": 0,
            "server_to_client_tcp_packets": 0,
            "client_to_server_payload_packets": 0,
            "server_to_client_payload_packets": 0,
            "packet_timestamp_regressions": 0,
            "packet_timestamp_wall_clock_offset_min_seconds": None,
            "packet_timestamp_wall_clock_offset_max_seconds": None,
            "new_flow_keys_created": 0,
            "packets_added_to_existing_flow_keys": 0,
            "flows_expired": 0,
            "flows_accepted": 0,
            "incomplete_target_flows_discarded": 0,
            "non_target_flows_rejected": 0,
        }
        self._last_packet_timestamp = None

    def record_captured_packet(self, packet, timestamp):
        self.diagnostics["packets_captured"] += 1

        if (
            self._last_packet_timestamp is not None
            and timestamp < self._last_packet_timestamp
        ):
            self.diagnostics["packet_timestamp_regressions"] += 1

        self._last_packet_timestamp = timestamp
        timestamp_offset = timestamp - time.time()
        offset_min = self.diagnostics[
            "packet_timestamp_wall_clock_offset_min_seconds"
        ]
        offset_max = self.diagnostics[
            "packet_timestamp_wall_clock_offset_max_seconds"
        ]
        self.diagnostics[
            "packet_timestamp_wall_clock_offset_min_seconds"
        ] = (
            timestamp_offset
            if offset_min is None
            else min(offset_min, timestamp_offset)
        )
        self.diagnostics[
            "packet_timestamp_wall_clock_offset_max_seconds"
        ] = (
            timestamp_offset
            if offset_max is None
            else max(offset_max, timestamp_offset)
        )

        if IP not in packet or TCP not in packet:
            return

        ip = packet[IP]
        tcp = packet[TCP]
        flags = int(tcp.flags)
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)

        if syn and ack:
            self.diagnostics["tcp_syn_ack_packets"] += 1
        elif syn:
            self.diagnostics["tcp_syn_packets"] += 1

        if ack:
            self.diagnostics["tcp_ack_packets"] += 1
        if flags & 0x01:
            self.diagnostics["tcp_fin_packets"] += 1
        if flags & 0x04:
            self.diagnostics["tcp_rst_packets"] += 1

        client_to_server = (
            ip.src == "172.28.0.10"
            and ip.dst == "172.29.0.10"
            and int(tcp.dport) == 8080
        )
        server_to_client = (
            ip.src == "172.29.0.10"
            and ip.dst == "172.28.0.10"
            and int(tcp.sport) == 8080
        )

        if client_to_server:
            self.diagnostics["client_to_server_tcp_packets"] += 1
            if len(tcp.payload) > 0:
                self.diagnostics["client_to_server_payload_packets"] += 1
        elif server_to_client:
            self.diagnostics["server_to_client_tcp_packets"] += 1
            if len(tcp.payload) > 0:
                self.diagnostics["server_to_client_payload_packets"] += 1

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
            is_new_flow = False

        elif reverse_key in self.flows:
            flow_key = reverse_key
            is_new_flow = False

        else:
            flow_key = forward_key
            is_new_flow = True
            self.diagnostics["new_flow_keys_created"] += 1

            self.flows[flow_key] = Flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                start_time=timestamp,
                last_time=timestamp,
            )

        if not is_new_flow:
            self.diagnostics["packets_added_to_existing_flow_keys"] += 1

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

        self.diagnostics["flows_expired"] += len(completed)
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
    Live traffic -> 100-flow window -> frozen inference
    -> DetectionEventAdapter -> MitigationController.
    """

    CLIENT_IP = "172.28.0.10"
    SERVER_IP = "172.29.0.10"
    SERVER_PORT = 8080

    def __init__(self):
        self.inference = InferenceAdapter()

        from mitigation.detection.detection_event_adapter import (
            DetectionEventAdapter
        )
        from mitigation.controller.mitigation_controller import (
            MitigationController
        )

        self.event_adapter = DetectionEventAdapter(
            inference_adapter=self.inference
        )

        # First integrated test: no real firewall actions.
        self.controller = MitigationController(dry_run=False)

        self.flow_buffer: List[Flow] = []

    def add_flow(self, flow: Flow):

        self.flow_buffer.append(flow)

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
            [flow.to_features() for flow in window],
            columns=STAT_FEATURES,
        )

        print("\n" + "=" * 70)
        print("LIVE DETECTION WINDOW READY")
        print("=" * 70)

        try:
            # Generate the exact existing 48-feature representation.
            engineered_features = (
                self.inference.window_to_features(flow_window)
            )

            # Reuse the existing detection and AnomalyFlow logic.
            event = self.event_adapter.create_event(
                engineered_features=engineered_features,
                client=self.CLIENT_IP,
                server=self.SERVER_IP,
                port=self.SERVER_PORT,
                diagnostic_base_features=flow_window,
            )

            print("\nLIVE DETECTION EVENT")
            print("-" * 70)
            print(event)

            # Pass the event to the existing mitigation controller.
            mitigation_result = self.controller.process_event(event)

            print("\nLIVE MITIGATION RESULT")
            print("-" * 70)
            print(mitigation_result)

        except Exception as exc:
            print("\nLIVE INTEGRATION ERROR")
            print("-" * 70)
            print(f"{type(exc).__name__}: {exc}")
            raise



def handle_completed_flow(flow):
    # Normalize flows first observed in the server-to-client direction.
    forward_target = (
        flow.protocol == 6
        and flow.src_ip == "172.28.0.10"
        and flow.dst_ip == "172.29.0.10"
        and flow.dst_port == 8080
    )

    reverse_target = (
        flow.protocol == 6
        and flow.src_ip == "172.29.0.10"
        and flow.dst_ip == "172.28.0.10"
        and flow.src_port == 8080
    )

    if reverse_target:
        flow = Flow(
            src_ip=flow.dst_ip,
            dst_ip=flow.src_ip,
            src_port=flow.dst_port,
            dst_port=flow.src_port,
            protocol=flow.protocol,
            start_time=flow.start_time,
            last_time=flow.last_time,
            forward_packets=flow.backward_packets,
            backward_packets=flow.forward_packets,
            forward_bytes=flow.backward_bytes,
            backward_bytes=flow.forward_bytes,
            packet_lengths=list(flow.packet_lengths),
        )
        forward_target = True

    if not forward_target:
        collector.diagnostics["non_target_flows_rejected"] += 1
        return

    if flow.total_packets < 2:
        collector.diagnostics["incomplete_target_flows_discarded"] += 1
        print(
            "Discarded incomplete target flow: "
            f"{flow.total_packets} packet(s), "
            f"fwd={flow.forward_packets}, "
            f"bwd={flow.backward_packets}, "
            f"{flow.src_ip}:{flow.src_port} -> "
            f"{flow.dst_ip}:{flow.dst_port}"
        )
        return

    collector.diagnostics["flows_accepted"] += 1
    detection_pipeline.add_flow(flow)


def packet_handler(packet):
    timestamp = float(packet.time)
    collector.record_captured_packet(packet, timestamp)

    # Finalize idle 5-tuples before looking up this packet. Otherwise, a
    # reused tuple can refresh an expired flow and merge two connections.
    expired = collector.expire_flows(timestamp)

    for completed_flow in expired:
        handle_completed_flow(completed_flow)

    collector.process_packet(
        packet,
        timestamp=timestamp,
    )


def main():
    global collector
    global detection_pipeline

    collector = FlowCollector()
    detection_pipeline = LiveDetectionPipeline()
    shutdown_requested = False

    def request_shutdown(signum, frame):
        nonlocal shutdown_requested
        shutdown_requested = True

    previous_handlers = {
        signal.SIGINT: signal.getsignal(signal.SIGINT),
        signal.SIGTERM: signal.getsignal(signal.SIGTERM),
    }

    print("=" * 70)
    print("STEALTHGUARD LIVE FLOW COLLECTOR")
    print("=" * 70)

    print("\nInterface: cp-gateway eth1")
    print("Capturing client-side traffic...")
    print("100 completed flows -> frozen ML inference")
    print("Press Ctrl+C to stop.\n")

    try:
        signal.signal(signal.SIGINT, request_shutdown)
        signal.signal(signal.SIGTERM, request_shutdown)

        while not shutdown_requested:
            sniff(
                iface="eth1",
                prn=packet_handler,
                store=False,
                timeout=1,
            )

            # Expire stale flows even when no packets arrive.
            current_time = time.time()

            expired = collector.expire_flows(current_time)

            for completed_flow in expired:
                handle_completed_flow(completed_flow)

    except PermissionError:
        print("\nERROR: Packet capture requires root privileges.")
        print("Run the collector with sudo.")
    except KeyboardInterrupt:
        print("\nCapture interrupted.")
    finally:
        for sig, previous_handler in previous_handlers.items():
            signal.signal(sig, previous_handler)

        print("\nStopping capture and finalizing remaining flows...")
        completed = collector.flush()

        print(f"\nFlows remaining at shutdown: {len(completed)}")

        for flow in completed:
            handle_completed_flow(flow)

        print(
            "Shutdown complete. "
            f"Flows still buffered for inference: "
            f"{len(detection_pipeline.flow_buffer)}/{WINDOW_SIZE}"
        )
        print("\nCollector diagnostics:")
        for name, value in collector.diagnostics.items():
            print(f"  {name}: {value}")


if __name__ == "__main__":
    main()