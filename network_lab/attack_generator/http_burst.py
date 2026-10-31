import time
import urllib.error
import urllib.request

TARGET = "http://172.29.0.10:8080/health"
REQUESTS = 100
DELAY_SECONDS = 0.1
MAX_ATTEMPTS_PER_REQUEST = 5

print(f"Target: {TARGET}")
print(f"Requests: {REQUESTS}")
print(f"Delay: {DELAY_SECONDS}s")

successful_requests = 0

while successful_requests < REQUESTS:
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
                f"{successful_requests}/{REQUESTS}: "
                f"HTTP 200 ({len(body)} response bytes)"
            )
            time.sleep(DELAY_SECONDS)
            break
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            if attempt == MAX_ATTEMPTS_PER_REQUEST:
                raise RuntimeError(
                    f"Request {request_number}/{REQUESTS} failed after "
                    f"{MAX_ATTEMPTS_PER_REQUEST} attempts"
                ) from exc

            print(
                f"Request {request_number}/{REQUESTS} attempt "
                f"{attempt} failed; retrying: {exc}"
            )
            time.sleep(DELAY_SECONDS)

print(f"Traffic test complete: {successful_requests}/{REQUESTS} HTTP 200 responses.")
