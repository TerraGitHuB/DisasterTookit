'''This code is a port of dogbert's code for finding the bios password on dell machines. I wanted to use as few languages as possible, and so need to translate to python.'''

from enum import Enum
import struct
import time


class BiosType(Enum):
    t595B = 0
    tD35B = 1
    tA95B = 2
    t2A7B = 3
    t1D3B = 4
    t3A5B = 5
    t1F5A = 6
    t1F66 = 7
    t6FF1 = 8

class SerialType(Enum):
    fSVCTAG = 0
    fHDDSN = 1
    fHDDold = 2

bSuffix = ["595B", "D35B", "A95B", "2A7B", "1D3B", "3A5B", "1F5A", "1F66", "6FF1"]
scancods = "\x00\x1B1234567890-=\x08\x09qwertyuiop[]\x0D\xFFasdfghjkl;'`\xFF\\zxcvbnm,./"

chartabl2A7B = "012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0"
chartabl1D3B = "0BfIUG1kuPvc8A9Nl5DLZYSno7Ka6HMgqsJWm65yCQR94b21OTp7VFX2z0jihE33d4xtrew0"
chartabl1F66 = "0ewr3d4xtUG1ku0BfIp7VFb21OTSno7KDLZYqsJWa6HMgCQR94m65y9Nl5Pvc8AjihE3X2z0"
chartabl6FF1 = "08rptBxfbGVMz38IiSoeb360MKcLf4QtBCbWVzmH5wmZUcRR5DZG2xNCEv1nFtzsZB2bw1X0"


MD5magic = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
]
def initData():
    outData[0:4] = struct.pack('<I', 0x67452301)
    outData[4:8] = struct.pack('<I', 0xEFCDAB89)
    outData[8:12] = struct.pack('<I', 0x98BADCFE)
    outData[12:16] = struct.pack('<I', 0x10325476)

def enc0F2(num1, num2, num3):
    return (((~num3 ^ num2) & num1) ^ ~num3)

def enc0F4(num1, num2, num3):
    return ((~num2 ^ num1) ^ num3)

def enc0F5(num1, num2, num3):
    return ((~num1 | ~num3) ^ num2)

def enc1F2(num1, num2, num3):
    return (((num3 ^ num2) & num1) ^ num3)

def enc1F3(num1, num2, num3):
    return (((num1 ^ num2) & num3) ^ num2)

def enc1F4(num1, num2, num3):
    return ((num2 ^ num1) ^ num3)

def enc1F5(num1, num2, num3):
    return ((num1 | ~num3) ^ num2)

def encF3(num1, num2, num3):
    return (((num1 ^ num2) & num3) ^ num2)

def enc1F1(func, num1, num2, num3, key):
    return func(num1, num2, num3) + key

def enc0F1(func, num1, num2, num3, key):
    return func(num1, num2, num3) - key

def rol(t, bitsrot):
    return (t >> (32-bitsrot)) | (t << bitsrot)


def enc0F6(func, num1, num2, num3, num4, key, rot):
        return ((func(num1, num2, num3) + num4 - key) << rot) | ((func(num1, num2, num3) + num4 - key) >> (32 - rot)) + num1
def enc0F7(func, num1, num2, num3, num4, key, rot):
        return 



def blockEncodeF(outdata, encblock, func1, func2, func3, func4, func5):
    S = [[7, 12, 17, 22], [5, 9, 14, 20], [4, 11, 16, 23], [6, 10, 15, 21]]
    A, B, C, D, t, i = outdata[0], outdata[1], outdata[2], outdata[3], 0, 0
    for i in range(64):
        t = MD5magic[i]
        if i >> 4 == 0:
            t = A + func1(func2)

def blockEncode3A5B(outdata, encblock):
    A=outdata[0]
    B=outdata[1]
    C=outdata[2]
    D=outdata[3]
    for i in range(5):
        for j in range(4):
           B = enc0F6(enc0F2, C, A, D, B, MD5magic[4*j] + encblock[4*j], 7)
           D = enc0F6(enc0F2,B,C,A,D,MD5magic[4*j+1]+encblock[4*j+1],12)
           A = enc0F6(enc0F2,D,B,C,A,MD5magic[4*j+2]+encblock[4*j+2],17)
           C = enc0F6(enc0F2,A,D,B,C,MD5magic[4*j+3]+encblock[4*j+3],22)
        for j in range(4):
            B = enc0F6(encF3,C,A,D,B,MD5magic[4*(j+4)]+encblock[4*j+1],5)
            D = enc0F6(encF3,B,C,A,D,MD5magic[4*(j+4)+1]+encblock[(4*j+6)&0xF],9)
            A = enc0F6(encF3,D,B,C,A,MD5magic[4*(j+4)+2]+encblock[(4*j-5)&0xF],14)
            C = enc0F6(encF3,A,D,B,C,MD5magic[4*(j+4)+3]+encblock[4*j],20)
        for j in range(3):
            B = enc0F6(enc0F5,C,A,D,B,MD5magic[4*(11-j)]+encblock[(4*j-7)&0xF],4)
            D = enc0F6(enc0F5,B,C,A,D,MD5magic[4*(11-j)+1]+encblock[(4*j-4)&0xF],11)
            A = enc0F6(enc0F5,D,B,C,A,MD5magic[4*(11-j)+2]+encblock[4*j-1],16)
            C = enc0F6(enc0F5,A,D,B,C,MD5magic[4*(11-j)+3]+encblock[(4*j+2)&0xF],23)
        for j in range(3):
            B = enc0F6(enc0F5,C,A,D,B,MD5magic[4*(15-j)]+encblock[(4*j+4)&0xF],6)
            D = enc0F6(enc0F5,B,C,A,D,MD5magic[4*(15-j)+1]+encblock[(4*j-5)&0xF],10)
            A = enc0F6(enc0F5,D,B,C,A,MD5magic[4*(15-j)+2]+encblock[4*j+2],15)
            C = enc0F6(enc0F5,A,D,B,C,MD5magic[4*(15-j)+3]+encblock[(4*j-7)&0xF],21)
        outdata[0] += B
        outdata[1] += C
        outdata[2] += A
        outdata[3] += D

def blockEncode1F66(outdata, encblock):
    A = outdata[0]
    B = outdata[1]
    C = outdata[2]
    D = outdata[3]

    for i in range(17):
        A = A | 0x100097
        B = B ^ 0xA0008
        C = C | (0x60606161 - i)
        D = D ^ (0x50501010 + i)
        for j in range(4):
            A = enc0F6(enc0F2,B,C,D,A,MD5magic[16+4*j]+encblock[4*j],7)
            D = enc0F6(enc0F2,A,B,C,D,MD5magic[16+4*j+1]+encblock[4*j+1],12)
            C = enc0F6(enc0F2,D,A,B,C,MD5magic[16+4*j+2]+encblock[4*j+2],17)
            B = enc0F6(enc0F2,C,D,A,B,MD5magic[16+4*j+3]+encblock[4*j+3],22)
        for j in range(4):
            A = enc0F6(encF3,B,C,D,A,MD5magic[4*(3-j)+48]+encblock[4*j+1],5)
            D = enc0F6(encF3,A,B,C,D,MD5magic[4*(3-j)+48+1]+encblock[(4*j+6)&0xF],9)
            C = enc0F6(encF3,D,A,B,C,MD5magic[4*(3-j)+48+2]+encblock[(4*j-5)&0xF],14)
            B = enc0F6(encF3,C,D,A,B,MD5magic[4*(3-j)+48+3]+encblock[4*j],20)
        for j in range(3):
            B = enc0F6(enc0F4,C,D,A,B,MD5magic[4*(3-j)+32+3]+encblock[4*j+2],23)
            C = enc0F6(enc0F4,D,A,B,C,MD5magic[4*(3-j)+32+2]+encblock[(4*j-1)&0xF],16)
            D = enc0F6(enc0F4,A,B,C,D,MD5magic[4*(3-j)+32+1]+encblock[(4*j-4)&0xF],11)
            A = enc0F6(enc0F4,B,C,D,A,MD5magic[4*(3-j)+32]+encblock[(4*j-7)&0xF],4)
        for j in range(3):
            B = enc0F6(enc0F5,C,D,A,B,MD5magic[4*j+3]+encblock[(4*j-7)&0xF],21)
            C = enc0F6(enc0F5,D,A,B,C,MD5magic[4*j+2]+encblock[4*j+2],15)
            D = enc0F6(enc0F5,A,B,C,D,MD5magic[4*j+1]+encblock[(4*j-5)&0xF],10)
            A = enc0F6(enc0F5,B,C,D,A,MD5magic[4*j]+encblock[(4*j+4)&0xF],6)
        outdata[0] += A
        outdata[1] += B
        outdata[2] += C
        outdata[3] += D
    for i in range(21):
        A = A | 0x97
        B = B ^ 0x08
        C = C | 0x50501010
        D = D ^ 0x60606161
        for i in range(3):
           B = enc0F6(enc0F4,C,D,A,B,MD5magic[4*(3-j)+32+3]+encblock[4*j+2],23)
           C = enc0F6(enc0F4,D,A,B,C,MD5magic[4*(3-j)+32+2]+encblock[(4*j-1)&0xF],16)
           D = enc0F6(enc0F4,A,B,C,D,MD5magic[4*(3-j)+32+1]+encblock[(4*j-4)&0xF],11)
           A = enc0F6(enc0F4,B,C,D,A,MD5magic[4*(3-j)+32]+encblock[(4*j-7)&0xF],4)
        for i in range(3):
            B = enc0F6(enc0F5,C,D,A,B,MD5magic[4*(3-j)+48+3]+encblock[(4*j-7)&0xF],21)
            C = enc0F6(enc0F5,D,A,B,C,MD5magic[4*(3-j)+48+2]+encblock[(4*j+2)],15)
            D = enc0F6(enc0F5,A,B,C,D,MD5magic[4*(3-j)+48+1]+encblock[(4*j-5)&0xF],10)
            A = enc0F6(enc0F5,B,C,D,A,MD5magic[4*(3-j)+48]+encblock[4*j+4&0xF],6)
        for i in range(4):
            A = enc0F6(enc0F2,B,C,D,A,MD5magic[4*j]+encblock[4*j],7)
            D = enc0F6(enc0F2,A,B,C,D,MD5magic[4*j+1]+encblock[(4*j+1)],12)
            C = enc0F6(enc0F2,D,A,B,C,MD5magic[4*j+2]+encblock[(4*j+2)],17)
            B = enc0F6(enc0F2,C,D,A,B,MD5magic[4*j+3]+encblock[4*j+3],22)
        for i in range(4):
            A = enc0F6(encF3,B,C,D,A,MD5magic[16+4*j]+encblock[4*j+1],5)
            D = enc0F6(encF3,A,B,C,D,MD5magic[16+4*j+1]+encblock[(4*j+6)&0xF],9)
            C = enc0F6(encF3,D,A,B,C,MD5magic[16+4*j+2]+encblock[(4*j-5)&0xF],14)
            B = enc0F6(encF3,C,D,A,B,MD5magic[16+4*j+3]+encblock[4*j],20);
        outdata[0] += A
        outdata[1] += B
        outdata[2] += C
        outdata[3] += D
def blockEncode6FF1(outdata, encblock):
    A = outdata[0]
    B = outdata[1]
    C = outdata[2]
    D = outdata[3]

    for i in range(23):
        A |= 0xA08097
        B ^= 0xA010908
        C |= 0x60606161-i
        D ^= 0x50501010+1
        for j in range(4):
            A = enc0F6(enc0F2,A,B,C,D,MD5magic[4*j+32]+encblock[4*j],7)
            D = enc0F6(enc0F2,D,A,B,C,MD5magic[4*j+32+1]+encblock[4*j+1],12)
            C = enc0F6(enc0F2,C,D,A,B,MD5magic[4*j+32+2]+encblock[4*j+2],17)
            B = enc0F6(enc0F2,B,C,D,A,MD5magic[4*j+32+3]+encblock[4*j+3],22)
        for j in range(4):
            A = enc0F6(encF3,A,B,C,D,MD5magic[4*j]+encblock[4*j+1],5)
            D = enc0F6(encF3,D,A,B,C,MD5magic[4*j+1]+encblock[(4*j+6)&0xF],9)
            C = enc0F6(encF3,C,D,A,B,MD5magic[4*j+2]+encblock[(4*j-5)&0xF],14)
            B = enc0F6(encF3,B,C,D,A,MD5magic[4*j+3]+encblock[4*j],20)
        for j in range(3):
            B = enc0F6(enc0F4,B,C,D,A,MD5magic[4*j+16+3]+encblock[4*j+2],23)
            C = enc0F6(enc0F4,C,D,A,B,MD5magic[4*j+16+2]+encblock[(4*j-1)&0xF],16)
            D = enc0F6(enc0F4,D,A,B,C,MD5magic[4*j+16+1]+encblock[(4*j-4)&0xF],11)
            A = enc0F6(enc0F4,A,B,C,D,MD5magic[4*j+16]+encblock[(4*j-7)&0xF],4)
        for j in range(3):
            B = enc0F6(enc0F5,B,C,D,A,MD5magic[4*j+48+3]+encblock[(4*j-7)&0xF],21)
            C = enc0F6(enc0F5,C,D,A,B,MD5magic[4*j+48+2]+encblock[4*j+2],15)
            D = enc0F6(enc0F5,D,A,B,C,MD5magic[4*j+48+1]+encblock[(4*j-5)&0xF],10)
            A = enc0F6(enc0F5,A,B,C,D,MD5magic[4*j+48]+encblock[(4*j+4)&0xF],6)
        outdata[0] += A
        outdata[1] += B
        outdata[2] += C
        outdata[3] += D
    
    for i in range(17):
        A |= 0x100097
        B ^= 0xA0008
        C |= 0x50501010-i
        D ^= 0x60606161+i
        for j in range(3):
            B = enc0F6(enc0F4,B,C,D,A,MD5magic[4*j+16+3]+encblock[4*j+2],23)
            C = enc0F6(enc0F4,C,D,A,B,MD5magic[4*j+16+2]+encblock[(4*j-1)&0xF],16)
            D = enc0F6(enc0F4,D,A,B,C,MD5magic[4*j+16+1]+encblock[(4*j-4)&0xF],11)
            A = enc0F6(enc0F4,A,B,C,D,MD5magic[4*j+16]+encblock[(4*j-7)&0xF],4)
        for j in range(4):
            A = enc0F6(enc0F5,A,B,C,D,MD5magic[4*j+32]+encblock[(4*j+4)&0xF],6)
            D = enc0F6(enc0F5,D,A,B,C,MD5magic[4*j+32+1]+encblock[(4*j-5)&0xF],10)
            C = enc0F6(enc0F5,C,D,A,B,MD5magic[4*j+32+2]+encblock[4*j+2],15)
            B = enc0F6(enc0F5,B,C,D,A,MD5magic[4*j+32+3]+encblock[(4*j-7)&0xF],21)
        for j in range(3):
            B = enc0F6(enc0F2,B,C,D,A,MD5magic[4*j+3]+encblock[4*j+3],22)
            C = enc0F6(enc0F2,C,D,A,B,MD5magic[4*j+2]+encblock[4*j+2],17)
            D = enc0F6(enc0F2,D,A,B,C,MD5magic[4*j+1]+encblock[4*j+1],12)
            A = enc0F6(enc0F2,A,B,C,D,MD5magic[4*j]+encblock[4*j],7)
        for j in range(4):
            A = enc0F6(encF3,A,B,C,D,MD5magic[4*j+48]+encblock[4*j+1],5)
            D = enc0F6(encF3,D,A,B,C,MD5magic[4*j+48+1]+encblock[(4*j+6)&0xF],9)
            C = enc0F6(encF3,C,D,A,B,MD5magic[4*j+48+2]+encblock[(4*j-5)&0xF],14)
            B = enc0F6(encF3,B,C,D,A,MD5magic[4*j+48+3]+encblock[4*j],20)
        outdata[0] += A
        outdata[1] += B
        outdata[2] += C
        outdata[3] += D
def blockEncode1D3B(outdata, encblock):
    A = outdata[0]
    B = outdata[1]
    C = outdata[2]
    D = outdata[3]
    for i in range(21):
        A |= 0x97
        B ^= 8
        C |= 0x60606161-i
        D ^= 0x50501010+i
        for j in range(4):
            A = enc0F6(enc0F2,B,C,D,A,MD5magic[4*j]+encblock[4*j],7)
            D = enc0F6(enc0F2,A,B,C,D,MD5magic[4*j+1]+encblock[4*j+1],12)
            C = enc0F6(enc0F2,D,A,B,C,MD5magic[4*j+2]+encblock[4*j+2],17)
            B = enc0F6(enc0F2,C,D,A,B,MD5magic[4*j+3]+encblock[4*j+3],22)
        for j in range(4):
            A = enc0F6(encF3,B,C,D,A,MD5magic[4*(j+4)]+encblock[4*j+1],5)
            D = enc0F6(encF3,A,B,C,D,MD5magic[4*(j+4)+1]+encblock[(4*j+6)&0xF],9)
            C = enc0F6(encF3,D,A,B,C,MD5magic[4*(j+4)+2]+encblock[(4*j-5)&0xF],14)
            B = enc0F6(encF3,C,D,A,B,MD5magic[4*(j+4)+3]+encblock[4*j],20)
        for j in range(3):
            B = enc0F6(enc0F4,C,D,A,B,MD5magic[4*(3-j)+32+3]+encblock[4*j+2],23)
            C = enc0F6(enc0F4,D,A,B,C,MD5magic[4*(3-j)+32+2]+encblock[(4*j-1)&0xF],16)
            D = enc0F6(enc0F4,A,B,C,D,MD5magic[4*(3-j)+32+1]+encblock[(4*j-4)&0xF],11)
            A = enc0F6(enc0F4,B,C,D,A,MD5magic[4*(3-j)+32]+encblock[(4*j-7)&0xF],4)
        for j in range(3):
            B = enc0F6(enc0F5,C,D,A,B,MD5magic[4*(3-j)+48+3]+encblock[(4*j-7)&0xF],21)
            C = enc0F6(enc0F5,D,A,B,C,MD5magic[4*(3-j)+48+2]+encblock[4*j+2],15)
            D = enc0F6(enc0F5,A,B,C,D,MD5magic[4*(3-j)+48+1]+encblock[(4*j-5)&0xF],10)
            A = enc0F6(enc0F5,B,C,D,A,MD5magic[4*(3-j)+48]+encblock[(4*j+4)&0xF],6)
        outdata[0] += A
        outdata[1] += B
        outdata[2] += C
        outdata[3] += D
def blockEncode(outdata, encblock, btype:BiosType):
    match btype:
        case BiosType.tD35B:
            blockEncodeF(outdata,encblock,enc1F1,enc1F2,enc1F3,enc1F4,enc1F5)
        case BiosType.t1F66:
            blockEncode1F66(outdata,encblock)
        case BiosType.t1D3B:
            blockEncode1D3B(outdata,encblock)
        case BiosType.t6FF1:
            blockEncode6FF1(outdata,encblock)
        case BiosType.t3A5B:
            blockEncode3A5B(outdata,encblock)
        

        

