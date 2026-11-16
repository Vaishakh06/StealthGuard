import argparse
import os
import time
import urllib.error
import urllib.request

TARGET = "http://172.29.0.10:8080/health"
REQUESTS = 100
DELAY_SECONDS = 0.1
MAX_ATTEMPTS_PER_REQUEST = 5

# Shared ground truth file (mounted from host via Docker volume).
# The host-side flow collector reads this file each inference window.
GROUND_TRUTH_PATH = "/workspace/attack_generator/ground_truth.txt"


def main():
    parser = argparse.ArgumentParser(
        description="StealthGuard HTTP burst traffic generator (BENIGN class)"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=REQUESTS,
        help=f"Number of HTTP requests to generate (default: {REQUESTS})",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DELAY_SECONDS,
        help=f"Delay between requests in seconds (default: {DELAY_SECONDS})",
    )
    parser.add_argument(
        "--ground-truth",
        dest="ground_truth",
        choices=["BENIGN", "TCP_DDoS", "UDP_DDoS"],
        help="Expected 3-class label for evaluation metadata (written to shared ground truth file)",
    )
    args = parser.parse_args()

    # Write expected 3-class ground truth to shared file for the host-side
    # flow collector. The compose file mounts ./attack_generator to
    # /workspace/attack_generator in cp-client, so this file is visible to
    # the collector on the host at network_lab/attack_generator/ground_truth.txt.
    # This lets the user set ground truth per attack test without restarting
    # the collector. Ground truth is evaluation metadata only and never
    # influences model inference, predictions, or mitigation decisions.
    # If --ground-truth is omitted, no value is written so the collector sees
    # ground_truth as None for that window.
    if args.ground_truth:
        try:
            with open(GROUND_TRUTH_PATH, "w", encoding="utf-8") as f:
                f.write(args.ground_truth.strip().upper() + "\n")
            print(f"Ground truth written to {GROUND_TRUTH_PATH}: {args.ground_truth}")
        except OSError as exc:
            print(
                f"Warning: could not write ground truth to {GROUND_TRUTH_PATH}: "
                f"{exc}"
            )

    print(f"Target: {TARGET}")
    print(f"Requests: {args.count}")
    print(f"Delay: {args.delay}s")

    successful_requests = 0

    while successful_requests < args.count:
        request_number = successful_requests + 1

        for attempt in range(1, MAX_ATTEMPTS_PER_REQUEST + 1):
            request = urllib.request.Request(
                TARGET,
                headers={"Connection": "close"},
            )

            try:
                with urllib.request.urlopen(request, timeout=3) as response:
                    body = response.read()
                    if response.status != 200:
                        raise RuntimeError(
                            f"Unexpected HTTP status {response.status}"
                        )

                successful_requests += 1
                print(
                    f"{successful_requests}/{args.count}: "
                    f"HTTP 200 ({len(body)} response bytes)"
                )
                time.sleep(args.delay)
                break
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                if attempt == MAX_ATTEMPTS_PER_REQUEST:
                    raise RuntimeError(
                        f"Request {request_number}/{args.count} failed after "
                        f"{MAX_ATTEMPTS_PER_REQUEST} attempts"
                    ) from exc

                print(
                    f"Request {request_number}/{args.count} attempt "
                    f"{attempt} failed; retrying: {exc}"
                )
                time.sleep(args.delay)

    print(f"Traffic test complete: {successful_requests}/{args.count} HTTP 200 responses.")


if __name__ == "__main__":
    main()
