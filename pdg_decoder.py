"""

Single-file pure Python PDG decoder/copier CLI.



Usage:

  pdg_decoder.py <input_path> [-o OUTPUT_DIR] [-r] [-j JOBS] [--overwrite] [--fail-fast]

"""



from __future__ import annotations



import argparse

import concurrent.futures as cf

import logging

import os

import sys

import time



import hashlib

import io

import shutil

import struct

from dataclasses import dataclass

from functools import lru_cache

from pathlib import Path



from PIL import Image





LOG = logging.getLogger("pdg_converter")





def _setup_logging(level_name: str) -> None:

    level = getattr(logging, level_name.upper(), logging.INFO)

    logging.basicConfig(

        level=level,

        format="[%(levelname)s] %(filename)s:%(lineno)d - %(message)s",

        stream=sys.stdout,

    )





def _u16le(b, off):

    return b[off] | (b[off + 1] << 8)





def _u32le(b, off):

    return b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)





@dataclass

class _PdgContainer:

    header: bytearray

    payload: bytes

    pdg_type: int





def _c_mod(a, b):

    # Match C/C++ signed remainder semantics (truncate toward zero).

    return a - int(a / b) * b





def _xor_with_key(data, key):

    out = bytearray(data)

    klen = len(key)

    if klen == 0:

        return out

    for i in range(len(out)):

        k = key[i % klen]

        out[i] = (out[i] & (~k & 0xFF)) | (k & (~out[i] & 0xFF))

    return out





def _tea_like_decrypt_block_16(block16, key_words):

    v = list(struct.unpack("<4I", block16))

    k = key_words

    v5 = 0xE3779B90

    delta = 0x61C88647

    for _ in range(4):

        v[3] = (v[3] - ((v[0] + v5) ^ (k[1] + (v[0] >> 5)) ^ (k[2] + ((v[0] << 4) & 0xFFFFFFFF)))) & 0xFFFFFFFF

        v[2] = (v[2] - ((v[3] + v5) ^ (k[3] + (v[3] >> 5)) ^ (k[0] + ((v[3] << 4) & 0xFFFFFFFF)))) & 0xFFFFFFFF

        v[1] = (v[1] - ((v[2] + v5) ^ (k[2] + ((v[2] << 4) & 0xFFFFFFFF)) ^ (k[3] + (v[2] >> 5)))) & 0xFFFFFFFF

        v[0] = (v[0] - (((v[1] + v5) ^ (k[1] + (v[1] >> 5)) ^ (k[0] + ((v[1] << 4) & 0xFFFFFFFF)))) ) & 0xFFFFFFFF

        v5 = (v5 + delta) & 0xFFFFFFFF



        v[3] = (v[3] - ((v[0] + v5) ^ (k[1] + (v[0] >> 5)) ^ (k[2] + ((v[0] << 4) & 0xFFFFFFFF)))) & 0xFFFFFFFF

        v[2] = (v[2] - ((v[3] + v5) ^ (k[3] + (v[3] >> 5)) ^ (k[0] + ((v[3] << 4) & 0xFFFFFFFF)))) & 0xFFFFFFFF

        v[1] = (v[1] - ((v[2] + v5) ^ (k[2] + ((v[2] << 4) & 0xFFFFFFFF)) ^ (k[3] + (v[2] >> 5)))) & 0xFFFFFFFF

        v[0] = (v[0] - (((v[1] + v5) ^ (k[1] + (v[1] >> 5)) ^ (k[0] + ((v[1] << 4) & 0xFFFFFFFF)))) ) & 0xFFFFFFFF

        v5 = (v5 + delta) & 0xFFFFFFFF



        v[3] = (v[3] - ((v[0] + v5) ^ (k[1] + (v[0] >> 5)) ^ (k[2] + ((v[0] << 4) & 0xFFFFFFFF)))) & 0xFFFFFFFF

        v[2] = (v[2] - ((v[3] + v5) ^ (k[3] + (v[3] >> 5)) ^ (k[0] + ((v[3] << 4) & 0xFFFFFFFF)))) & 0xFFFFFFFF

        v[1] = (v[1] - ((v[2] + v5) ^ (k[2] + ((v[2] << 4) & 0xFFFFFFFF)) ^ (k[3] + (v[2] >> 5)))) & 0xFFFFFFFF

        v[0] = (v[0] - (((v[1] + v5) ^ (k[1] + (v[1] >> 5)) ^ (k[0] + ((v[1] << 4) & 0xFFFFFFFF)))) ) & 0xFFFFFFFF

        v5 = (v5 + delta) & 0xFFFFFFFF



        v[3] = (v[3] - ((v[0] + v5) ^ (k[1] + (v[0] >> 5)) ^ (k[2] + ((v[0] << 4) & 0xFFFFFFFF)))) & 0xFFFFFFFF

        v[2] = (v[2] - ((v[3] + v5) ^ (k[3] + (v[3] >> 5)) ^ (k[0] + ((v[3] << 4) & 0xFFFFFFFF)))) & 0xFFFFFFFF

        v[1] = (v[1] - ((v[2] + v5) ^ (k[2] + ((v[2] << 4) & 0xFFFFFFFF)) ^ (k[3] + (v[2] >> 5)))) & 0xFFFFFFFF

        v[0] = (v[0] - (((v[1] + v5) ^ (k[1] + (v[1] >> 5)) ^ (k[0] + ((v[1] << 4) & 0xFFFFFFFF)))) ) & 0xFFFFFFFF

        v5 = (v5 + delta) & 0xFFFFFFFF

    return struct.pack("<4I", *v)





def _md5_key_words(data):

    d = hashlib.md5(data).digest()

    return list(struct.unpack("<4I", d))





def _decode_type_1_to_5(header, payload):

    t = header[15]

    out = bytearray(payload)

    key48 = bytes(header[64:112])

    if t == 1:

        return bytes(_xor_with_key(out, b"3.141592"))

    if t == 2:

        kw = _md5_key_words(key48)

        for i in range(0, len(out) & ~0xF, 16):

            out[i:i + 16] = _tea_like_decrypt_block_16(bytes(out[i:i + 16]), kw)

        return bytes(out)

    if t == 4:

        kw = _md5_key_words(key48)

        kw_bytes = bytearray(struct.pack("<4I", *kw))

        # IDA: sub_046B80(..., a4=8, a5=8) -> only first 8 key bytes are mixed.

        kw_bytes[:8] = _xor_with_key(bytearray(kw_bytes[:8]), b"SSREADER")

        kw2 = list(struct.unpack("<4I", bytes(kw_bytes)))

        for i in range(0, len(out) & ~0xF, 16):

            out[i:i + 16] = _tea_like_decrypt_block_16(bytes(out[i:i + 16]), kw2)

        return bytes(out)

    if t >= 3:

        kw = _md5_key_words(key48)

        kw_bytes = bytearray(struct.pack("<4I", *kw))

        if t == 5:

            mix = b"e#fgF%3*"

        else:

            mix = b"SUPERSTAR4PDG2.0"

        # IDA: only first 8 key bytes are mixed for type>=3 path.

        kw_bytes[:8] = _xor_with_key(bytearray(kw_bytes[:8]), mix[:8] if len(mix) >= 8 else mix)

        kw2 = list(struct.unpack("<4I", bytes(kw_bytes)))

        for i in range(0, len(out) & ~0xF, 16):

            out[i:i + 16] = _tea_like_decrypt_block_16(bytes(out[i:i + 16]), kw2)

        return bytes(out)

    return bytes(out)





_TYPE_11_KEY_215 = bytes.fromhex(

    "3133326a6b73646961753334756b6a617364666c6b6a2140233233346166646a693738232532333441446620761c3d2d0773646b6a3930383334323c4144463e2f2377253474356f387577726f75796f75686a38393334303338703335307c2b5f53444661647772213233346761734d2c2e737066646c705b574565793364667366677366343839305e3a3921402335362638393338343937383930373839303534696f657275615e337e2132262a285f2b2a283830772675696466733967686964666f7765723233392d383974616572432821376100"

)

_TYPE_11_KEY_130 = (

    b"Afgasdkol!@#$564746Lfat0[9i FDLAas090132!$@##$2354(*^78~*54sdfakl;ml;lak;j2a#$2342!@#128-reg;o[werqPWEQRioADSF1234&*(6908_)55454!"

)



_RUN_WHITE_CODES = [

    (2, 2, 3), (2, 3, 2), (3, 2, 1), (3, 3, 4), (4, 2, 6), (4, 3, 5), (5, 3, 7),

    (6, 4, 9), (6, 5, 8), (7, 4, 10), (7, 5, 11), (7, 7, 12), (8, 4, 13), (8, 7, 14),

    (9, 1, -2), (9, 24, 15), (10, 1, -2), (10, 8, 18), (10, 15, 64), (10, 23, 16),

    (10, 24, 17), (10, 55, 0), (11, 1, -2), (11, 8, 1792), (11, 12, 1856),

    (11, 13, 1920), (11, 23, 24), (11, 24, 25), (11, 40, 23), (11, 55, 22),

    (11, 103, 19), (11, 104, 20), (11, 108, 21), (12, 0, -2), (12, 1, -1),

    (12, 18, 1984), (12, 19, 2048), (12, 20, 2112), (12, 21, 2176), (12, 22, 2240),

    (12, 23, 2304), (12, 28, 2368), (12, 29, 2432), (12, 30, 2496), (12, 31, 2560),

    (12, 36, 52), (12, 39, 55), (12, 40, 56), (12, 43, 59), (12, 44, 60),

    (12, 51, 320), (12, 52, 384), (12, 53, 448), (12, 55, 53), (12, 56, 54),

    (12, 82, 50), (12, 83, 51), (12, 84, 44), (12, 85, 45), (12, 86, 46),

    (12, 87, 47), (12, 88, 57), (12, 89, 58), (12, 90, 61), (12, 91, 256),

    (12, 100, 48), (12, 101, 49), (12, 102, 62), (12, 103, 63), (12, 104, 30),

    (12, 105, 31), (12, 106, 32), (12, 107, 33), (12, 108, 40), (12, 109, 41),

    (12, 200, 128), (12, 201, 192), (12, 202, 26), (12, 203, 27), (12, 204, 28),

    (12, 205, 29), (12, 210, 34), (12, 211, 35), (12, 212, 36), (12, 213, 37),

    (12, 214, 38), (12, 215, 39), (12, 218, 42), (12, 219, 43), (13, 74, 640),

    (13, 75, 704), (13, 76, 768), (13, 77, 832), (13, 82, 1280), (13, 83, 1344),

    (13, 84, 1408), (13, 85, 1472), (13, 90, 1536), (13, 91, 1600), (13, 100, 1664),

    (13, 101, 1728), (13, 108, 512), (13, 109, 576), (13, 114, 896), (13, 115, 960),

    (13, 116, 1024), (13, 117, 1088), (13, 118, 1152), (13, 119, 1216),

]



_RUN_BLACK_CODES = [

    (4, 7, 2), (4, 8, 3), (4, 11, 4), (4, 12, 5), (4, 14, 6), (4, 15, 7),

    (5, 7, 10), (5, 8, 11), (5, 18, 128), (5, 19, 8), (5, 20, 9), (5, 27, 64),

    (6, 3, 13), (6, 7, 1), (6, 8, 12), (6, 23, 192), (6, 24, 1664), (6, 42, 16),

    (6, 43, 17), (6, 52, 14), (6, 53, 15), (7, 3, 22), (7, 4, 23), (7, 8, 20),

    (7, 12, 19), (7, 19, 26), (7, 23, 21), (7, 24, 28), (7, 36, 27), (7, 39, 18),

    (7, 40, 24), (7, 43, 25), (7, 55, 256), (8, 2, 29), (8, 3, 30), (8, 4, 45),

    (8, 5, 46), (8, 10, 47), (8, 11, 48), (8, 18, 33), (8, 19, 34), (8, 20, 35),

    (8, 21, 36), (8, 22, 37), (8, 23, 38), (8, 26, 31), (8, 27, 32), (8, 36, 53),

    (8, 37, 54), (8, 40, 39), (8, 41, 40), (8, 42, 41), (8, 43, 42), (8, 44, 43),

    (8, 45, 44), (8, 50, 61), (8, 51, 62), (8, 52, 63), (8, 53, 0), (8, 54, 320),

    (8, 55, 384), (8, 74, 59), (8, 75, 60), (8, 82, 49), (8, 83, 50), (8, 84, 51),

    (8, 85, 52), (8, 88, 55), (8, 89, 56), (8, 90, 57), (8, 91, 58), (8, 100, 448),

    (8, 101, 512), (8, 103, 640), (8, 104, 576), (9, 1, -2), (9, 152, 1472),

    (9, 153, 1536), (9, 154, 1600), (9, 155, 1728), (9, 204, 704), (9, 205, 768),

    (9, 210, 832), (9, 211, 896), (9, 212, 960), (9, 213, 1024), (9, 214, 1088),

    (9, 215, 1152), (9, 216, 1216), (9, 217, 1280), (9, 218, 1344), (9, 219, 1408),

    (10, 1, -2), (11, 1, -2), (11, 8, 1792), (11, 12, 1856), (11, 13, 1920),

    (12, 0, -2), (12, 1, -1), (12, 18, 1984), (12, 19, 2048), (12, 20, 2112),

    (12, 21, 2176), (12, 22, 2240), (12, 23, 2304), (12, 28, 2368), (12, 29, 2432),

    (12, 30, 2496), (12, 31, 2560),

]



_MODE_CODES = [

    (1, 1, 3), (3, 1, 2), (3, 2, 7), (3, 3, 4), (4, 1, 1), (6, 2, 8), (6, 3, 5),

    (7, 0, 12), (7, 2, 9), (7, 3, 6), (8, 2, 11), (9, 6, 11), (10, 14, 11), (10, 15, 10),

]



_RUN_WHITE_LUT = {(l, k): v for l, k, v in _RUN_WHITE_CODES}

_RUN_BLACK_LUT = {(l, k): v for l, k, v in _RUN_BLACK_CODES}

_MODE_LUT = {(l, k): v for l, k, v in _MODE_CODES}





def _build_prefix_tables(codes, max_bits):

    size = 1 << max_bits

    sym = [-9999] * size

    blen = [0] * size

    # shorter prefix wins

    for l, k, v in sorted(codes, key=lambda x: x[0]):

        tail = 1 << (max_bits - l)

        base = k << (max_bits - l)

        for i in range(tail):

            idx = base | i

            if blen[idx] == 0:

                sym[idx] = v

                blen[idx] = l

    return sym, blen





_WHITE_SYM, _WHITE_LEN = _build_prefix_tables(_RUN_WHITE_CODES, 13)

_BLACK_SYM, _BLACK_LEN = _build_prefix_tables(_RUN_BLACK_CODES, 12)

_MODE_SYM, _MODE_LEN = _build_prefix_tables(_MODE_CODES, 10)





def _tbl_32():

    t = [0] * 32

    t[0] = 1

    t[1] = 1

    pos = 1

    for _ in range(5):

        v3 = t[pos]

        v4 = t[pos - 1]

        pos += 6

        v5 = v3 + v4

        t[pos - 5] = v5

        v6 = v5 + v3

        t[pos - 4] = v6

        v7 = v6 + v5

        t[pos - 3] = v7

        t[pos - 2] = v7 + v6

        t[pos - 1] = v7 + v6 + v7

        t[pos] = v7 + v6 + v7 + v6 + v7

    return t





def _tbl_64():

    t = [0] * 64

    t[0] = 2

    t[1] = 3

    v1 = 1

    v2 = 2

    cur = 5

    idx = 2

    while v2 < 64:

        if cur not in (25, 49, 121, 169, 289):

            t[idx] = cur

            idx += 1

            v2 += 1

        v1 += 1

        if v1 == 3:

            cur += 4

            v1 = 1

        else:

            cur += 2

    return t





def _op_48b80(a, b, buf):

    if a == b:

        return

    hi = a

    lo = b

    off = 17

    if a < b:

        hi = b

        lo = a

    if hi - lo == 17:

        off = 19

    v = buf[hi] ^ buf[hi + off]

    buf[hi] = buf[lo] ^ buf[lo + off]

    buf[lo] = v





def _op_48bf0(a, b, buf):

    if a == b:

        return

    lo = min(a, b)

    hi = max(a, b)

    span = hi - lo - 1

    if span == 0:

        return

    out = bytearray(span)

    x = buf[lo] ^ buf[hi]

    for i in range(span):

        out[span - i - 1] = x ^ buf[lo + 1 + i]

    buf[lo + 1:hi] = out





def _op_48cc0(a, b, buf):

    if a == b:

        return

    mid = (a >> 1) + (b >> 1)

    v = buf[a]

    if mid != a:

        v ^= buf[mid]

    buf[a] = (v - b) & 0xFF





def _decode_type_11_to_1c(header, payload):

    t = header[15]

    if t < 0x11 or t > 0x1C:

        return bytes(payload), False



    if len(payload) == 0:

        return bytes(payload), False



    v48 = _tbl_32()

    v49 = _tbl_64()

    v51 = bytearray(_TYPE_11_KEY_215 + b"\x00")

    v50 = bytearray(_TYPE_11_KEY_130 + b"\x00")



    b94 = header[94]

    v5 = header[28] | (header[29] << 8)

    v6 = header[16]

    v7 = header[18]

    v8 = (v5 >> 8) & 0xFF

    v9 = (v7 + header[28] + v6) & 0xFF

    v10 = (v6 - v7) & 0xFF

    v_or = (v7 | v6) & 0xFF

    v11 = (v9 * v10) & 0xFFFF

    v12 = (v6 * v8) & 0xFF

    v13 = (b94 + (v6 * v7 * v6)) & 0xFF

    v_mul = (v7 * v6) & 0xFF



    v24 = (v_or * v_mul + (v8 * v12) - v11 + v13 + 250) & 0x1FF

    v36 = ((v_or * v_or) - (v12 * v13) + (v11 * v_mul) + 250) & 0x1FF



    idx = (v12 * v12 + v9 + v10 + v_or + v_mul + v8 + v6 + v51[v13 % 215]) % 0xD7

    idx2 = (v12 * v12 + v9 + v10 + v_or + v_mul + v8 + v6 + v50[v13 % 130]) % 0x82

    v14 = (v51[idx] * v50[idx2]) & 0xFFFFFFFF



    v15 = v51[(v10 * v_mul - v8) % 0xD7]

    v25 = v14 & 0x800001FF

    v16 = v48[(v5 >> 8) & 0x1F]

    v37 = (v50[v6 % 130] * v15) & 0x800001FF

    v17 = v49[(v6 * v8) & 0x3F]

    v26 = v16 & 0x1FF

    v38 = v17 & 0x1FF

    v28 = v24

    v29 = ((v36 * (v14 & 0x1FF)) - v24) & 0x1FF

    v18 = (v38 * v50[v38 % 0x82]) & 0xFFFFFFFF

    v27 = v49[((v17 & 0xFF) * v50[(v26 * v51[v26 % 0xD7]) % 0x82]) & 0x3F] & 0x1FF

    v39 = v48[((v16 & 0xFF) * v51[v18 % 0xD7]) & 0x1F] & 0x1FF

    v19 = ((v14 & 0x1FF) * v39) & 0xFFFF

    v40 = ((v36 * v19) - ((v17 & 0x1FF) * v27) + (v37 * v37) + 250) & 0x1FF

    v41 = ((v24 * v24) + ((v16 & 0x1FF) * (v16 & 0x1FF)) - (v36 * v36)) & 0x1FF

    v30 = ((v17 & 0x1FF) - (v24 * (v14 & 0x1FF))) & 0x1FF

    v43 = (v27 * v39) & 0x1FF

    v42 = ((v36 * v37) + ((v16 & 0x1FF) * (v17 & 0x1FF)) - v19 + v27 + 250) & 0x1FF

    v32 = (v36 + v24) & 0x1FF

    v31 = (v27 - (v36 * (v17 & 0x1FF))) & 0x1FF

    v34 = (v30 + v42 - (v14 & 0x1FF)) & 0x1FF

    v44 = (v50[v36 % 0x82] + v51[v40 % 0xD7]) & 0x800001FF

    v33 = (v29 + v37) & 0x1FF

    v35 = (v31 + v33 - v39) & 0x1FF

    v45 = v49[((v14 & 0xFF) * (((v36 & 0xFF) * (v14 & 0xFF) - (v24 & 0xFF) + (v37 & 0xFF)) & 0xFF)) & 0x3F] & 0x1FF

    v46 = v49[v51[v30 % 0xD7] & 0x3F] & 0x1FF

    v47 = v48[v50[v30 % 0x82] & 0x1F] & 0x1FF



    arr = [0] * 41

    seq = [

        v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35,

        v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47,

    ]

    arr[17:17 + len(seq)] = seq



    out = bytearray(payload)

    a = arr[t] & 0xFFFF

    b = arr[t + 12] & 0xFFFF

    if t <= 0x14:

        _op_48b80(a, b, out)

    elif t <= 0x18:

        _op_48bf0(a, b, out)

    else:

        _op_48cc0(a, b, out)

    return bytes(out), True





class _BitReader:

    def __init__(self, data):

        self.data = data

        self.pos = 0

        self.bitbuf = 0  # msb-first

        self.bits_left = 0



    def _fill_to(self, n):

        while self.bits_left < n and self.pos < len(self.data):

            self.bitbuf = ((self.bitbuf << 8) | self.data[self.pos]) & ((1 << 64) - 1)

            self.pos += 1

            self.bits_left += 8

        return self.bits_left >= n



    def peek(self, n):

        if not self._fill_to(n):

            return None

        return (self.bitbuf >> (self.bits_left - n)) & ((1 << n) - 1)



    def drop(self, n):

        if n > self.bits_left:

            return False

        self.bits_left -= n

        if self.bits_left == 0:

            self.bitbuf = 0

        else:

            self.bitbuf &= (1 << self.bits_left) - 1

        return True



    def read1(self):

        v = self.peek(1)

        if v is None:

            return None

        self.drop(1)

        return v



    def remaining_bits(self):

        return self.bits_left + (len(self.data) - self.pos) * 8





def _decode_mode_57b30(br):

    idx = br.peek(10)

    if idx is not None:

        bit_len = _MODE_LEN[idx]

        if bit_len != 0:

            br.drop(bit_len)

            return _MODE_SYM[idx]

    code = 0

    for code_len in range(1, 11):

        b = br.read1()

        if b is None:

            return 13

        code = (code << 1) | b

        v = _MODE_LUT.get((code_len, code))

        if v is not None:

            return v

    return 13





def _decode_white_56870(br):

    idx = br.peek(13)

    if idx is not None:

        bit_len = _WHITE_LEN[idx]

        if bit_len != 0:

            br.drop(bit_len)

            return _WHITE_SYM[idx]

    code = 0

    for code_len in range(1, 14):

        b = br.read1()

        if b is None:

            return -1

        code = (code << 1) | b

        v = _RUN_WHITE_LUT.get((code_len, code))

        if v is not None:

            return v

    return -1





def _decode_black_57170(br):

    idx = br.peek(12)

    if idx is not None:

        bit_len = _BLACK_LEN[idx]

        if bit_len != 0:

            br.drop(bit_len)

            return _BLACK_SYM[idx]

    code = 0

    for code_len in range(1, 13):

        b = br.read1()

        if b is None:

            return -1

        code = (code << 1) | b

        v = _RUN_BLACK_LUT.get((code_len, code))

        if v is not None:

            return v

    return -1





def _decode_white_run(br):

    total = 0

    loops = 0

    while True:

        loops += 1

        if loops > 256:

            return -1

        v = _decode_white_56870(br)

        if v < 0:

            return v

        total += v

        if v < 64:

            return total





def _decode_black_run(br):

    total = 0

    loops = 0

    while True:

        loops += 1

        if loops > 256:

            return -1

        v = _decode_black_57170(br)

        if v < 0:

            return v

        total += v

        if v < 64:

            return total





def _decode_line_57d60(br, prev_runs, curr_runs, width):

    def _pr(i):

        if i < 0:

            return 0

        if i >= len(prev_runs):

            return width

        return prev_runs[i]



    v4 = 0

    idx = 0

    ref_idx = 0

    v7 = False

    steps = 0

    max_steps = max(width * 128, 65536)



    while True:

        steps += 1

        if steps > max_steps:

            return -1

        prev_v4 = v4

        mode = _decode_mode_57b30(br)

        if mode == 1:

            v4 = _pr(ref_idx + 1)

            ref_idx += 2

        elif mode == 2:

            if v7:

                d1 = _decode_black_run(br)

                if d1 < 0:

                    return -1

                v12 = d1 + v4

                curr_runs[idx] = v12

                d2 = _decode_white_run(br)

            else:

                d1 = _decode_white_run(br)

                if d1 < 0:

                    return -1

                v12 = d1 + v4

                curr_runs[idx] = v12

                d2 = _decode_black_run(br)

            if d2 < 0:

                return -1

            v4 = d2 + v12

            idx += 2

            curr_runs[idx - 1] = v4

            while ref_idx < (len(prev_runs) - 2) and _pr(ref_idx) <= v4:

                ref_idx += 2

        elif mode == 3:

            v4 = _pr(ref_idx)

            ref_idx += 1

            curr_runs[idx] = v4

            idx += 1

            v7 = not v7

        elif mode == 4:

            v4 = _pr(ref_idx) + 1

            ref_idx += 1

            curr_runs[idx] = v4

            idx += 1

            v7 = not v7

        elif mode == 5:

            v4 = _pr(ref_idx) + 2

            ref_idx += 1

            curr_runs[idx] = v4

            idx += 1

            v7 = not v7

        elif mode == 6:

            v4 = _pr(ref_idx) + 3

            ref_idx += 1

            curr_runs[idx] = v4

            idx += 1

            v7 = not v7

        elif mode == 7:

            v4 = _pr(ref_idx)

            ref_idx += 1

            if v4:

                v4 -= 1

            curr_runs[idx] = v4

            idx += 1

            v7 = not v7

        elif mode == 8:

            t = _pr(ref_idx)

            ref_idx += 1

            v4 = 0 if t < 2 else t - 2

            curr_runs[idx] = v4

            idx += 1

            v7 = not v7

        elif mode == 9:

            t = _pr(ref_idx)

            ref_idx += 1

            v4 = 0 if t < 3 else t - 3

            curr_runs[idx] = v4

            idx += 1

            v7 = not v7

        elif mode == 13:

            # Some streams end with truncated tail bits; DLL decoding still

            # converges by effectively passing reference transitions through.

            if br.remaining_bits() <= 64:

                v4 = _pr(ref_idx)

                ref_idx += 1

                curr_runs[idx] = v4

                idx += 1

                v7 = not v7

            else:

                return -1



        if v4 >= width:

            curr_runs[idx] = v4

            curr_runs[idx + 1] = v4

            curr_runs[idx + 2] = v4

            curr_runs[idx + 3] = v4

            return idx





def _fill_row_from_runs_56710(runs, n, row_bytes):

    out = bytearray(row_bytes)

    if n - 1 <= 0:

        return out

    pairs = ((n - 2) >> 1) + 1

    p = 0

    for _ in range(pairs):

        e = runs[p + 1]

        s = runs[p]

        if e > 8 * row_bytes:

            e = 8 * row_bytes

        if s < e:

            s_bit = s & 7

            s_byte = s >> 3

            v13 = (255 >> s_bit) & 0xFF

            e_byte = e >> 3

            v16 = (~(255 >> (e & 7))) & 0xFF

            if e_byte == s_byte:

                out[s_byte] |= (v16 & v13) & 0xFF

            else:

                out[s_byte] |= v13

                if v16:

                    out[e_byte] |= v16

                gap = e_byte - s_byte

                if gap > 1:

                    out[s_byte + 1:e_byte] = b"\xFF" * (gap - 1)

        p += 2

    return out





def _decode_bitonal_57f10_to_bmp(payload, x_pix, y_pix):

    if x_pix <= 0 or y_pix <= 0:

        return None

    # IDA loader can over-read one extra dword when reloading bit cache.

    br = _BitReader(payload + b"\x00" * 8)

    row_words = (x_pix >> 5) + (1 if (x_pix & 0x1F) else 0)

    row_bytes = row_words * 4

    out = bytearray(row_bytes * y_pix)

    prev_runs = [0] + [x_pix] * 8191

    curr_runs = [0] + [x_pix] * 8191

    for y in range(y_pix):

        n = _decode_line_57d60(br, prev_runs, curr_runs, x_pix)

        if n < 0:

            return None

        row = _fill_row_from_runs_56710(curr_runs, n, row_bytes)

        start = y * row_bytes

        out[start:start + row_bytes] = row

        prev_runs, curr_runs = curr_runs, prev_runs



    # sub_057F10 output is top-down; BMP with positive height is bottom-up.

    rows = [bytes(out[i * row_bytes:(i + 1) * row_bytes]) for i in range(y_pix)]

    rows.reverse()

    pixel_data = b"".join(rows)



    palette = b"\x00\x00\x00\x00\xff\xff\xff\x00"

    off_bits = 14 + 40 + len(palette)

    bf_size = off_bits + len(pixel_data)

    bmp = bytearray()

    bmp += b"BM"

    bmp += struct.pack("<I", bf_size)

    bmp += b"\x00\x00\x00\x00"

    bmp += struct.pack("<I", off_bits)

    bmp += struct.pack("<I", 40)

    bmp += struct.pack("<i", x_pix)

    bmp += struct.pack("<i", y_pix)

    bmp += struct.pack("<H", 1)

    bmp += struct.pack("<H", 1)

    bmp += struct.pack("<I", 0)

    bmp += struct.pack("<I", len(pixel_data))

    bmp += struct.pack("<I", 0)  # XPelsPerMeter

    bmp += struct.pack("<I", 0)  # YPelsPerMeter

    bmp += struct.pack("<I", 2)  # ClrUsed

    bmp += struct.pack("<I", 0)  # ClrImportant

    bmp += palette

    bmp += pixel_data

    return bytes(bmp)





def _magic_type(data):

    if data.startswith(b"AT&TFORM") and len(data) >= 16 and data[12:16] in (b"DJVU", b"DJVM"):

        return "djvu"

    if data.startswith(b"\xFF\xD8\xFF"):

        return "jpeg"

    if data.startswith(b"\x89PNG\r\n\x1a\n"):

        return "png"

    if data.startswith(b"GIF8"):

        return "gif"

    if data.startswith(b"BM"):

        return "bmp"

    if data.startswith(b"II*\x00") or data.startswith(b"MM\x00*"):

        return "tiff"

    return None





def _build_tiff_g4(raw_ccitt, x_pix, y_pix, white_is_zero):

    """

    Wrap raw CCITT Group4 bitstream into a minimal little-endian TIFF container.

    """

    entries = []



    def _add(tag, typ, cnt, val):

        entries.append((tag, typ, cnt, val))



    _add(256, 4, 1, x_pix)  # ImageWidth

    _add(257, 4, 1, y_pix)  # ImageLength

    _add(258, 3, 1, 1)  # BitsPerSample

    _add(259, 3, 1, 4)  # Compression=CCITT Group 4

    _add(262, 3, 1, 0 if white_is_zero else 1)  # PhotometricInterpretation

    _add(273, 4, 1, 0)  # StripOffsets (patched below)

    _add(278, 4, 1, y_pix)  # RowsPerStrip

    _add(279, 4, 1, len(raw_ccitt))  # StripByteCounts

    _add(277, 3, 1, 1)  # SamplesPerPixel



    ifd_size = 2 + 12 * len(entries) + 4

    data_offset = 8 + ifd_size

    entries[5] = (273, 4, 1, data_offset)



    ifd = struct.pack("<H", len(entries))

    for tag, typ, cnt, val in entries:

        ifd += struct.pack("<HHII", tag, typ, cnt, val)

    ifd += struct.pack("<I", 0)

    return b"II*\x00" + struct.pack("<I", 8) + ifd + raw_ccitt





def _decode_ccitt_g4_to_bmp_bytes(raw_ccitt, x_pix, y_pix):

    if x_pix <= 0 or y_pix <= 0:

        return None

    for white_is_zero in (False, True):

        tif = _build_tiff_g4(raw_ccitt, x_pix, y_pix, white_is_zero)

        try:

            with Image.open(io.BytesIO(tif)) as im:

                img = im.convert("1")

                buf = io.BytesIO()

                img.save(buf, format="BMP")

                return buf.getvalue()

        except Exception:

            pass

    return None





def _u32(x):

    return x & 0xFFFFFFFF





def _ror32(x, n):

    x &= 0xFFFFFFFF

    return ((x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)) & 0xFFFFFFFF





def _le32_at(buf, off):

    return struct.unpack_from("<I", buf, off)[0]





def _b0(x):

    return x & 0xFF





def _b1(x):

    return (x >> 8) & 0xFF





def _b2(x):

    return (x >> 16) & 0xFF





def _b3(x):

    return (x >> 24) & 0xFF





def _rva_to_file_off(pe_data, rva):

    if len(pe_data) < 0x40:

        return None

    e_lfanew = struct.unpack_from("<I", pe_data, 0x3C)[0]

    if e_lfanew + 24 > len(pe_data):

        return None

    if pe_data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":

        return None

    nsects = struct.unpack_from("<H", pe_data, e_lfanew + 6)[0]

    opt_size = struct.unpack_from("<H", pe_data, e_lfanew + 20)[0]

    sect_off = e_lfanew + 24 + opt_size

    for i in range(nsects):

        off = sect_off + i * 40

        if off + 40 > len(pe_data):

            break

        vsize = struct.unpack_from("<I", pe_data, off + 8)[0]

        vaddr = struct.unpack_from("<I", pe_data, off + 12)[0]

        raw_size = struct.unpack_from("<I", pe_data, off + 16)[0]

        raw_ptr = struct.unpack_from("<I", pe_data, off + 20)[0]

        span = max(vsize, raw_size)

        if vaddr <= rva < vaddr + span:

            return raw_ptr + (rva - vaddr)

    return None





@lru_cache(maxsize=1)

def _load_pdgthumb_tables():

    base = Path(__file__).resolve().parents[2]

    dll_path = base / "PdgThumbViewer_Ext_x64.dll"

    if not dll_path.exists():

        return None

    pe = dll_path.read_bytes()



    def read_rva(rva, size):

        off = _rva_to_file_off(pe, rva)

        if off is None or off + size > len(pe):

            return None

        return pe[off:off + size]



    kblock = read_rva(0x00C28F50, 8)

    rot = read_rva(0x00C28F60, 16)

    ksbox_b = read_rva(0x00C28F70, 512 * 4)

    spbox = read_rva(0x00C286CF, 2052)

    if not kblock or not rot or not ksbox_b or not spbox:

        return None



    ksbox = [struct.unpack_from("<I", ksbox_b, i * 4)[0] for i in range(512)]

    return {

        "master_key_words": list(struct.unpack("<2I", kblock)),

        "rot": list(rot),

        "ksbox": ksbox,

        "spbox": spbox,

    }





def _sub_08c750_schedule(key_words, tbl):

    d = tbl["ksbox"]

    rot = tbl["rot"]



    a0, a1 = key_words

    v6 = (a0 ^ (a1 >> 4)) & 0x0F0F0F0F

    v7 = _u32(v6 ^ a0)

    v8 = _u32((v6 << 4) ^ a1)

    v9 = (v8 ^ (v7 >> 4)) & 0x01010101

    t = _u32((v9 << 4) ^ v7)

    v10 = _u32(((t ^ (t >> 9)) & 0x550055) ^ ((((t ^ (t >> 9)) & 0x550055) << 9)) ^ t)

    t2 = _u32(v9 ^ v8)

    v11 = _u32(((t2 ^ (t2 >> 9)) & 0x550055) ^ ((((t2 ^ (t2 >> 9)) & 0x550055) << 9)) ^ t2)

    m = (v10 ^ (v10 >> 18)) & 0x3333

    v12 = _u32(m ^ (m << 18) ^ v10)

    m = (v11 ^ (v11 >> 18)) & 0x3333

    v13 = _u32(m ^ (m << 18) ^ v11)

    t3 = ((v13 ^ _b2(v13)) & 0xFF)

    v14 = _u32(t3 ^ (t3 << 16) ^ v13)



    out = [0] * 32

    for i in range(16):

        v15 = v14 & 0x0FFFFFFF

        v16 = v12 & 0x0FFFFFFF

        if rot[i]:

            v12 = _u32((v16 >> 2) | (v12 << 26))

            v18 = _u32((v15 >> 2) | (v15 << 26))

        else:

            v12 = _u32((v16 >> 1) | (v12 << 27))

            v18 = _u32((v15 >> 1) | (v15 << 27))

        v14 = v18

        v20 = (v18 >> 16) & 0xFF



        idx0 = (v12 & 0x3F)

        idx1 = (((_b1(v12) >> 1) & 0x3F) + 64)

        idx2 = ((_b2(v12) & 0x1D | (((_b2(v12) & 0x40) | ((_b2(v12) >> 5) & 4)) >> 1)) + 128)

        idx3 = ((_b3(v12) & 0xE | ((((_b1(v12) >> 5) | (v12 & 0xC0))) >> 2)) + 192)

        v21 = d[idx0] | d[idx1] | d[idx2] | d[idx3]



        idx4 = ((((v18 >> 8) & 0x3D) | ((((v18 >> 8) & 0xFF) >> 6) & 2)) + 320)

        idx5 = ((v20 & 0x3F) + 384)

        idx6 = (((v18 >> 24) & 0xD) | (((v20 & 0xC0) | ((((v18) & 0xFF) >> 4) & 8)) >> 2)) + 448

        idx7 = ((v18 & 0x3F) + 256)

        v24 = d[idx7] | d[idx5] | d[idx4] | d[idx6]



        out[2 * i] = _u32((v21 & 0xFFFF) | ((v24 << 16) & 0xFFFFFFFF))

        out[2 * i + 1] = _u32((v21 >> 16) | (v24 & 0xFFFF0000))

    return out





def _f_08b780(x, ka, kb, spbox):

    mask = 0x3F3F3F3F

    a = (x ^ ka) & mask

    b = (kb ^ _ror32(x, 4)) & mask

    return _u32(

        _le32_at(spbox, 4 * _b0(a) + 1)

        | _le32_at(spbox, 4 * _b0(b) + 257)

        | _le32_at(spbox, 4 * _b1(a) + 513)

        | _le32_at(spbox, 4 * _b2(a) + 1025)

        | _le32_at(spbox, 4 * _b1(b) + 769)

        | _le32_at(spbox, 4 * _b3(a) + 1537)

        | _le32_at(spbox, 4 * _b2(b) + 1281)

        | _le32_at(spbox, 4 * _b3(b) + 1793)

    )





def _sub_08b780_enc(block_words, subkeys, spbox):

    left0, right0 = block_words

    v4 = (left0 ^ (right0 >> 4)) & 0x0F0F0F0F

    v5 = _u32(v4 ^ left0)

    v6 = _u32((v4 << 4) ^ right0)

    v7 = ((v6 ^ (v5 >> 16)) & 0xFFFF)

    v8 = _u32(v7 ^ v6)

    v9 = _u32((v7 << 16) ^ v5)

    v10 = (v9 ^ (v8 >> 2)) & 0x33333333

    v11 = _u32(v10 ^ v9)

    v12 = _u32((v10 << 2) ^ v8)

    v13 = (v12 ^ (v11 >> 8)) & 0x00FF00FF

    v14 = _u32(v13 ^ v12)

    v15 = _u32((v13 << 8) ^ v11)

    v16 = (v15 ^ (v14 >> 1)) & 0x55555555

    left = _u32(v16 ^ v15)

    right = _u32((v16 << 1) ^ v14)



    j = 0

    for _ in range(8):

        right = _u32(right ^ _f_08b780(left, subkeys[j], subkeys[j + 1], spbox))

        j += 2

        left = _u32(left ^ _f_08b780(right, subkeys[j], subkeys[j + 1], spbox))

        j += 2



    v50 = left

    v48 = right

    v51 = (v50 ^ (v48 >> 1)) & 0x55555555

    v52 = _u32(v51 ^ v50)

    v53 = _u32((v51 << 1) ^ v48)

    v54 = (v53 ^ (v52 >> 8)) & 0x00FF00FF

    v55 = _u32(v54 ^ v53)

    v56 = _u32((v54 << 8) ^ v52)

    v57 = (v56 ^ (v55 >> 2)) & 0x33333333

    v58 = _u32(v57 ^ v56)

    v59 = _u32((v57 << 2) ^ v55)

    v60 = ((v59 ^ (v58 >> 16)) & 0xFFFF)

    v61 = _u32(v60 ^ v59)

    v62 = _u32((v60 << 16) ^ v58)

    out0 = _u32(v61 ^ ((((v62 ^ (v61 >> 4)) & 0x0F0F0F0F) << 4)))

    out1 = _u32(v62 ^ ((v62 ^ (v61 >> 4)) & 0x0F0F0F0F))

    return [out0, out1]





def _build_a0_schedules(seed_words, tbl):

    k23d0 = _sub_08c750_schedule(tbl["master_key_words"], tbl)

    spbox = tbl["spbox"]



    v17, v18 = seed_words[0], seed_words[1]

    v17, v18 = _sub_08b780_enc([v17, v18], k23d0, spbox)

    k1fc0 = _sub_08c750_schedule([v17, v18], tbl)



    v17 ^= seed_words[2]

    v18 ^= seed_words[3]

    v17, v18 = _sub_08b780_enc([v17, v18], k23d0, spbox)

    k2040 = _sub_08c750_schedule([v17, v18], tbl)



    v14 = v17 ^ seed_words[0]

    v18 ^= seed_words[1]

    v17 = _u32(v14 ^ 0x80)

    v17, v18 = _sub_08b780_enc([v17, v18], k23d0, spbox)

    k20c0 = _sub_08c750_schedule([v17, v18], tbl)



    v15 = seed_words[2] ^ v17

    v18 ^= seed_words[3]

    v17 = _u32(v15 ^ 0x40)

    v17, v18 = _sub_08b780_enc([v17, v18], k23d0, spbox)

    k2140 = _sub_08c750_schedule([v17, v18], tbl)



    v16 = v17 ^ seed_words[0]

    v18 ^= seed_words[1]

    v17 = _u32(v16 ^ 0x20)

    v17, v18 = _sub_08b780_enc([v17, v18], k23d0, spbox)

    k21c0 = _sub_08c750_schedule([v17, v18], tbl)



    v12 = seed_words[3]

    v13 = _u32(seed_words[2] ^ v17 ^ 0x10)

    v18 ^= v12

    v17 = v13

    v17, v18 = _sub_08b780_enc([v17, v18], k23d0, spbox)

    k2240 = _sub_08c750_schedule([v17, v18], tbl)



    return {

        "k1fc0": k1fc0,

        "k2040": k2040,

        "k20c0": k20c0,

        "k2140": k2140,

        "k21c0": k21c0,

        "k2240": k2240,

        "spbox": spbox,

    }





def _sub_058c30_words(words4, sch):

    v9, v10, v11, v12 = words4

    spbox = sch["spbox"]

    e0, e1 = _sub_08b780_enc([v11, v12], sch["k2240"], spbox)

    v9 ^= e0

    v10 ^= e1

    e0, e1 = _sub_08b780_enc([v9, v10], sch["k21c0"], spbox)

    v11 ^= e0

    v12 ^= e1

    e0, e1 = _sub_08b780_enc([v11, v12], sch["k2140"], spbox)

    v9 ^= e0

    v10 ^= e1

    e0, e1 = _sub_08b780_enc([v9, v10], sch["k20c0"], spbox)

    v11 ^= e0

    v12 ^= e1

    e0, e1 = _sub_08b780_enc([v11, v12], sch["k2040"], spbox)

    v9 ^= e0

    v10 ^= e1

    e0, e1 = _sub_08b780_enc([v9, v10], sch["k1fc0"], spbox)

    return [_u32(v9), _u32(v10), _u32(e0 ^ v11), _u32(e1 ^ v12)]





def _decode_type_a0_to_af(header, payload):

    t = header[15]

    if (t & 0xF0) != 0xA0:

        return bytes(payload), False

    tbl = _load_pdgthumb_tables()

    if tbl is None:

        return bytes(payload), False



    out = bytearray(payload)



    if t == 0xAA:

        seeds = [8520200, 19005960, 8409144, 9568776]

    elif t == 0xAB:

        v3 = _u16le(header, 16)

        header[16:18] = header[18:20]

        header[18:20] = bytes((v3 & 0xFF, (v3 >> 8) & 0xFF))

        seeds = [

            _u32(_u32le(header, 12) ^ 0x820208),

            _u32(_u32le(header, 16) ^ 0x1220208),

            _u32(_u32le(header, 20) ^ 0x805038),

            _u32(_u32le(header, 24) ^ 0x920208),

        ]

    else:

        seeds = [

            _u32(_u32le(header, 32) ^ 0x820208),

            _u32(_u32le(header, 36) ^ 0x1220208),

            _u32(_u32le(header, 40) ^ 0x805038),

            _u32(_u32le(header, 44) ^ 0x920208),

        ]



    sch = _build_a0_schedules(seeds, tbl)

    for i in range(17):

        off = i * 32

        if off + 16 > len(out):

            break

        w = list(struct.unpack_from("<4I", out, off))

        nw = _sub_058c30_words(w, sch)

        struct.pack_into("<4I", out, off, *nw)



    header[15] = 0

    if t == 0xAC:

        w = (_u16le(header, 16) - 100) & 0xFFFF

        hh = (_u16le(header, 18) - 1000) & 0xFFFF

        header[16:18] = bytes((w & 0xFF, (w >> 8) & 0xFF))

        header[18:20] = bytes((hh & 0xFF, (hh >> 8) & 0xFF))

    return bytes(out), True





def _decode_flag56_preprocess(header, payload):

    if header[56] == 0:

        return bytes(payload), True

    if header[57] != 0x86:

        return bytes(payload), False

    tbl = _load_pdgthumb_tables()

    if tbl is None:

        return bytes(payload), False

    out = bytearray(payload)

    seeds = [850670129, 941241401, 8414468, 9568772]

    sch = _build_a0_schedules(seeds, tbl)

    for i in range(17):

        off = i * 32

        if off + 16 > len(out):

            break

        w = list(struct.unpack_from("<4I", out, off))

        nw = _sub_058c30_words(w, sch)

        struct.pack_into("<4I", out, off, *nw)

    header[56] = 0

    w = (_u16le(header, 16) - 49) & 0xFFFF

    header[16:18] = bytes((w & 0xFF, (w >> 8) & 0xFF))

    return bytes(out), True





def _parse_pdg_container(raw_bytes: bytes) -> _PdgContainer:

    header = bytearray(raw_bytes[:140])

    data_off = _u32le(header, 24)

    data_len = _u32le(header, 28)

    if data_off + data_len > len(raw_bytes):

        data_off = 140

        data_len = max(0, len(raw_bytes) - data_off)

    payload = raw_bytes[data_off:data_off + data_len]

    return _PdgContainer(header=header, payload=payload, pdg_type=header[15])





def _normalize_type10_header(header):

    # IDA sub_049330: PDG type 0x10 mutates width/height using bytes[104..107],

    # then falls through as type 0 path.

    v7 = (

        header[104]

        | (header[105] << 8)

        | (header[106] << 16)

        | (header[107] << 24)

    ) & 0xFFFFFFFF

    v8 = (v7 >> 16) & 0xFFFF

    hi_signed = v8 if v8 < 0x8000 else v8 - 0x10000

    v9 = v8 % 131

    lo = v7 & 0xFFFF

    lo = (lo - (_c_mod(hi_signed, 219) * _c_mod(hi_signed, 511)) + 20718) & 0xFFFF

    v10 = lo % 1019

    v7_lo2 = (v8 * lo) & 0xFFFF

    w = _u16le(header, 16)

    h = _u16le(header, 18)

    w = (v9 + w - v7_lo2 - v10) & 0xFFFF

    h = (v10 + h - v7_lo2 - v9) & 0xFFFF

    header[16:18] = bytes((w & 0xFF, (w >> 8) & 0xFF))

    header[18:20] = bytes((h & 0xFF, (h >> 8) & 0xFF))

    header[15] = 0





def _decrypt_payload(container: _PdgContainer):

    """

    Decode PDG payload in-place against header flags and type dispatch.

    Returns (payload, early_type). early_type is set when payload already has

    a recognized file magic and no more fallback probing is needed.

    """

    header = container.header

    payload = container.payload

    pdg_type = container.pdg_type



    # Common pre-process on header[56]/[57].

    payload, ok_56 = _decode_flag56_preprocess(header, payload)

    if not ok_56:

        return payload, _magic_type(payload)



    if pdg_type == 0x10 and len(header) >= 108:

        _normalize_type10_header(header)

        pdg_type = 0



    # type-specific preprocessors

    if 0x11 <= pdg_type <= 0x1C:

        payload, ok_11 = _decode_type_11_to_1c(header, payload)

        if ok_11:

            header[15] = 0

            pdg_type = 0



    if (pdg_type & 0xF0) == 0xA0:

        payload, ok_a0 = _decode_type_a0_to_af(header, payload)

        if ok_a0:

            header[15] = 0

            pdg_type = 0



    # legacy 1..5 decrypt

    if header[2] == 1 or pdg_type in (1, 2, 3, 4, 5):

        payload = _decode_type_1_to_5(header, payload)

    return payload, None





def _finalize_output(payload, header, x_pix, y_pix):

    """

    Prefer original payload format; only synthesize BMP for unknown bitonal streams.

    """

    out_type = _magic_type(payload)

    if out_type in ("djvu", "jpeg", "png", "gif", "tiff", "bmp"):

        return payload, out_type



    # IDA sub_047170 -> sub_057F10 path: non-24bpp payload is custom bitonal stream.

    if out_type is None and header[20] != 24:

        bmp = _decode_bitonal_57f10_to_bmp(payload, x_pix, y_pix)

        if bmp is not None:

            return bmp, "bmp"

    # Some PDG streams are raw CCITT G4-like bitonal payloads without file magic.

    # Try wrapping into TIFF/G4 for decoder fallback.

    if out_type is None and header[20] != 24:

        bmp = _decode_ccitt_g4_to_bmp_bytes(payload, x_pix, y_pix)

        if bmp is not None:

            return bmp, "bmp"

    return payload, out_type





def pdg_decode_pure_bytes(raw_bytes, x_pix, y_pix):

    if len(raw_bytes) < 140:

        return raw_bytes, _magic_type(raw_bytes)

    if raw_bytes[0:2] != b"HH":

        return raw_bytes, _magic_type(raw_bytes)



    container = _parse_pdg_container(raw_bytes)

    payload, early = _decrypt_payload(container)

    if early is not None:

        return payload, early

    return _finalize_output(payload, container.header, x_pix, y_pix)





def _xy_decoder_type10(header: bytearray) -> tuple[int, int]:

    key = header[104:108]

    x_lo = header[16]

    x_hi = header[17]

    y_lo = header[18]

    y_hi = header[19]



    key_32 = (key[3] << 24) + (key[2] << 16) + (key[1] << 8) + key[0]

    cipher_x = (x_hi << 8) + x_lo

    cipher_y = (y_hi << 8) + y_lo



    highword_key_32 = (key_32 & 0xFFFF0000) >> 16

    d = key_32 - (highword_key_32 - 219 * (((2510300521 * highword_key_32) >> 32) >> 7)) * (

        highword_key_32 - 511 * (((2151686161 * highword_key_32) >> 32) >> 8)

    ) + 20718

    d &= 0xFFFF

    c = highword_key_32 - 131 * (((1049152317 * highword_key_32) >> 32) >> 5)

    e = d * highword_key_32



    x_pix_t = c - e - d % 1019 + cipher_x

    y_pix_t = d % 1019 - c - e + cipher_y



    return (x_pix_t & 0xFFFF), (y_pix_t & 0xFFFF)





def _decode_size_for_pdg(raw: bytes) -> tuple[int, int]:

    if len(raw) < 140 or raw[0:2] != b"HH":

        return 0, 0



    header = bytearray(raw[:140])

    t = header[15]

    x = _u16le(header, 16)

    y = _u16le(header, 18)



    if t == 0xAA:

        return 1120, 1568

    if t == 0xAB:

        return y, x

    if t == 0xAC:

        return 1120, 1568

    if t == 0x10:

        return _xy_decoder_type10(header)

    return x, y





def _is_pdg_container(raw: bytes) -> bool:

    return len(raw) >= 140 and raw[0:2] == b"HH"





def _iter_input_files(input_path: Path, recursive: bool):

    if input_path.is_file():

        yield input_path

        return

    pattern = "**/*" if recursive else "*"

    for p in sorted(input_path.glob(pattern)):

        if not p.is_file():

            continue

        yield p





@dataclass

class _FileTaskResult:

    ok: bool

    log_message: str





def _process_file_task(src_path: str, root_path: str, output_dir_path: str, overwrite: bool) -> _FileTaskResult:

    src = Path(src_path)

    root = Path(root_path)

    output_dir = Path(output_dir_path)

    start = time.perf_counter()

    try:

        rel = src.relative_to(root)

        raw = src.read_bytes()

        if _is_pdg_container(raw):

            x_pix, y_pix = _decode_size_for_pdg(raw)

            out, out_type = pdg_decode_pure_bytes(raw, x_pix, y_pix)

            ext = out_type if out_type else "bin"

            dst_rel = rel.with_name(f"{rel.stem}.{ext}")

            dst = output_dir / dst_rel

            action = "decode"

        else:

            out = raw

            out_type = None

            dst = output_dir / rel

            action = "copy"



        dst.parent.mkdir(parents=True, exist_ok=True)

        if dst.exists() and not overwrite:

            raise RuntimeError("output exists (use --overwrite)")



        if action == "copy":

            shutil.copy2(src, dst)

            out_size = src.stat().st_size

        else:

            dst.write_bytes(out)

            out_size = len(out)



        elapsed = int((time.perf_counter() - start) * 1000)

        return _FileTaskResult(

            ok=True,

            log_message=(

                f"ok {src.name} -> {dst} action={action} "

                f"type={out_type} size={out_size}B time={elapsed}ms"

            ),

        )

    except Exception as exc:

        elapsed = int((time.perf_counter() - start) * 1000)

        return _FileTaskResult(ok=False, log_message=f"fail {src.name} error={exc!r} time={elapsed}ms")





def convert_path(

    input_path: Path,

    output_dir: Path,

    recursive: bool,

    overwrite: bool,

    fail_fast: bool,

    jobs: int,

) -> int:

    if not input_path.exists():

        LOG.error("input path not found: %s", input_path)

        return 2



    files = list(_iter_input_files(input_path, recursive))

    if not files:

        LOG.error("no files found: %s", input_path)

        return 3



    output_dir.mkdir(parents=True, exist_ok=True)

    root = input_path if input_path.is_dir() else input_path.parent



    ok = 0

    fail = 0

    max_workers = max(1, jobs)

    LOG.info("tasks=%d output_dir=%s jobs=%d", len(files), output_dir, max_workers)



    if max_workers == 1:

        for src in files:

            result = _process_file_task(str(src), str(root), str(output_dir), overwrite)

            if result.ok:

                LOG.info(result.log_message)

                ok += 1

            else:

                LOG.error(result.log_message)

                fail += 1

                if fail_fast:

                    break

    else:

        with cf.ProcessPoolExecutor(max_workers=max_workers) as executor:

            futures = {

                executor.submit(_process_file_task, str(src), str(root), str(output_dir), overwrite): src

                for src in files

            }

            cancel_requested = False

            for future in cf.as_completed(futures):

                if cancel_requested:

                    break
                try:

                    result = future.result()

                except Exception as exc:

                    result = _FileTaskResult(

                        ok=False,

                        log_message=f"fail {futures[future].name} error={exc!r} time=0ms",

                    )



                if result.ok:

                    LOG.info(result.log_message)

                    ok += 1

                else:

                    LOG.error(result.log_message)

                    fail += 1

                    if fail_fast:

                        cancel_requested = True

                        for f in futures:

                            if not f.done():

                                f.cancel()



    LOG.info("summary ok=%d fail=%d total=%d", ok, fail, ok + fail)

    return 0 if fail == 0 else 1





def build_parser() -> argparse.ArgumentParser:

    p = argparse.ArgumentParser(description="Decode PDG files and copy non-PDG files as-is")

    p.add_argument("input_path", help="Input file or directory")

    p.add_argument("-o", "--output-dir", default=None, help="Output directory (default: <input_path>_decrypted)")

    p.add_argument("-r", "--recursive", action="store_true", help="Recursively scan files when input is a directory")

    p.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 1)), help="Worker processes (default: CPU cores)")

    p.add_argument("--overwrite", action="store_true", default=True, help="Overwrite existing output files")

    p.add_argument("--fail-fast", action="store_true", default=True,help="Stop on first failure")

    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging level")

    return p





def main(argv: list[str] | None = None) -> int:


    args = build_parser().parse_args(argv)

    _setup_logging(args.log_level)

    input_path = Path(args.input_path)

    output_dir = Path(args.output_dir) if args.output_dir else Path(f"{args.input_path}_decrypted")

    return convert_path(

        input_path=input_path,

        output_dir=output_dir,

        recursive=args.recursive,

        overwrite=args.overwrite,

        fail_fast=args.fail_fast,

        jobs=args.jobs,

    )





if __name__ == "__main__":

    raise SystemExit(main(sys.argv[1:]))
