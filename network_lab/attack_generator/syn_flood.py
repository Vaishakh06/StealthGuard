from scapy.all import IP, TCP, send
import argparse

TARGET = "172.29.0.10"
SOURCE = "172.28.0.10"
PORT = 8080

parser = argparse.ArgumentParser()
parser.add_argument("--count", type=int, default=20)
parser.add_argument("--rate", type=int, default=5)
args = parser.parse_args()

if not (1 <= args.count <= 120):
    raise ValueError("Test count must be between 1 and 120")

if args.rate <= 0:
    raise ValueError("Rate must be positive")

packets = [
    IP(src=SOURCE, dst=TARGET) /
    TCP(sport=40000 + i, dport=PORT, flags="S", seq=1000 + i)
    for i in range(args.count)
]

print(f"Sending {args.count} SYN packets to {TARGET}:{PORT}")

send(packets, inter=1 / args.rate, verbose=False)

print("SYN test completed")