import time
import urllib.request

TARGET = "http://172.29.0.10:8080/health"
REQUESTS = 20
DELAY_SECONDS = 0.5

print(f"Target: {TARGET}")
print(f"Requests: {REQUESTS}")
print(f"Delay: {DELAY_SECONDS}s")

for i in range(1, REQUESTS + 1):
    try:
        with urllib.request.urlopen(TARGET, timeout=3) as response:
            print(f"{i}/{REQUESTS}: HTTP {response.status}")
    except Exception as exc:
        print(f"{i}/{REQUESTS}: FAILED - {exc}")

    time.sleep(DELAY_SECONDS)

print("Traffic test complete.")
