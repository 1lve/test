import random
import string
import math
import time
from collections import Counter

def test(b: bytearray):
    print("".join("{:02X}".format(x) for x in b))


class SM3:
    IV = [
        0x7380166F,
        0x4914B2B9,
        0x172442D7,
        0xDA8A0600,
        0xA96F30BC,
        0x163138AA,
        0xE38DEE4D,
        0xB0FB0E4E,
    ]

    def __T(self, x: int):
        if x < 16:
            return 0x79CC4519
        else:
            return 0x7A879D8A

    def __S(self, x: int, n: int):
        n &= 0x1F
        return (x << n | x >> (32 - n)) & 0xFFFFFFFF

    def __FF(self, j: int, x: int, y: int, z: int):
        if j < 16:
            return x ^ y ^ z
        else:
            return x & y | x & z | y & z

    def __GG(self, j: int, x: int, y: int, z: int):
        if j < 16:
            return x ^ y ^ z
        else:
            return (x & y) | ((0xFFFFFFFF ^ x) & z)

    def __p0(self, x: int):
        return x ^ self.__S(x, 9) ^ self.__S(x, 17)

    def __p1(self, x: int):
        return x ^ self.__S(x, 15) ^ self.__S(x, 23)

    def __padding(self, b: bytearray):
        n = len(b) * 8
        b.append(0x80)
        b += bytearray([0x00]) * ((56 - len(b)) % 64)
        b += bytearray([n >> (8 * i) & 0xFF for i in range(8)][::-1])

    def __split(self, b: bytearray):
        for i in range(0, len(b), 64):
            yield b[i:i + 64]

    def __hash(self, B: bytearray, V: list):
        r = V.copy()
        W = []
        for i in range(0, 64, 4):
            W.append(int.from_bytes(bytes(B[i:i + 4]), byteorder='big', signed=False))
        for j in range(16, 68):
            W.append(self.__p1(W[-16] ^ W[-9] ^ self.__S(W[-3], 15)) ^ self.__S(W[-13], 7) ^ W[-6])
        for j in range(64):
            SS1 = self.__S((self.__S(r[0], 12) + r[4] + self.__S(self.__T(j), j)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ self.__S(r[0], 12)
            TT1 = (self.__FF(j, r[0], r[1], r[2]) + r[3] + SS2 + (W[j] ^ W[j + 4])) & 0xFFFFFFFF
            TT2 = (self.__GG(j, r[4], r[5], r[6]) + r[7] + SS1 + W[j]) & 0xFFFFFFFF
            r = [TT1, r[0], self.__S(r[1], 9), r[2], self.__p0(TT2), r[4], self.__S(r[5], 19), r[6]]

        return [r[i] ^ V[i] for i in range(8)]

    def hash(self, byte_list):
        self.__padding(byte_list)
        V = SM3.IV.copy()
        for B in self.__split(byte_list):
            V = self.__hash(B, V)
        b = bytearray()
        for x in V:
            b += x.to_bytes(4, byteorder='big', signed=False)
        return b


hash = SM3().hash

def block(m):
    n = len(m)/128
    M = []
    for i in range(int(n)):
        M.append(m[0+128*i:128+128*i])
    return M

def random_num(n):
    z = []
    while len(z) < n:
        i = random.randint(0, pow(2,64))
        if i not in z:
            z.append(i)
    return z

def padding(message):
    m = bin(int(message,16))[2:]
    if len(m) != len(message)*4:
        m = '0'*(len(message)*4-len(m)) + m
    l = len(m)
    l_bin = '0'*(64-len(bin(l)[2:])) + bin(l)[2:]
    m = m + '1'
    m = m + '0'*(448-len(m)%512) + l_bin
    m = hex(int(m,2))[2:]
    return m


if __name__ == '__main__':
    '''sm3 = SM3()
    test(sm3.hash(bytearray(("abcd" * 16).encode())))'''
    print("碰撞:")
    start = time.time()
    random_value = []
    r = random_num(pow(2,16))
    for i in range(pow(2,16)):
       m = padding(str(r[i]))
       M = block(m)
       M_enc = SM3(M)
       tmp=""
       for k in M_enc:
           tmp += hex(k)[2:]
       random_value.append(tmp[:7])
    collision = dict(Counter(random_value))
    for key,value in collision.items():
       if value > 1:
           print (key)
    end = time.time()
    print("所用时间为：",end-start,"s")










    
