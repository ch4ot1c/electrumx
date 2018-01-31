
import struct


def deser_uint256(f):
    r = 0
    for i in range(8):
        t = struct.unpack("<I", f.read(4))[0]
        r += t << (i * 32)
    return r


def ser_uint256(u):
    rs = ""
    for i in range(8):
        rs += struct.pack("<I", u & 0xFFFFFFFF)
        u >>= 32
    return rs


def deser_vector(f, c):
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return deser_vector_with_len(f, c, nit)


def deser_vector_with_len(f, c, n):
    r = []
    for i in range(n):
        t = c()
        t.deserialize(f)
        r.append(t)
    return r


G1_PREFIX_MASK = 0x02
G2_PREFIX_MASK = 0x0a


class ZCProof(object):
    def __init__(self):
        self.g_A = None
        self.g_A_prime = None
        self.g_B = None
        self.g_B_prime = None
        self.g_C = None
        self.g_C_prime = None
        self.g_K = None
        self.g_H = None

    @staticmethod
    def deser_g1(f):
        leadingByte = struct.unpack("<B", f.read(1))[0]
        return {
            'y_lsb': leadingByte & 1,
            'x': f.read(32),
        }

    @staticmethod
    def deser_g2(f):
        leadingByte = struct.unpack("<B", f.read(1))[0]
        return {
            'y_gt': leadingByte & 1,
            'x': f.read(64),
        }

    def deserialize(self, f):
        self.g_A = ZCProof.deser_g1(f)
        self.g_A_prime = ZCProof.deser_g1(f)
        self.g_B = ZCProof.deser_g2(f)
        self.g_B_prime = ZCProof.deser_g1(f)
        self.g_C = ZCProof.deser_g1(f)
        self.g_C_prime = ZCProof.deser_g1(f)
        self.g_K = ZCProof.deser_g1(f)
        self.g_H = ZCProof.deser_g1(f)

    @staticmethod
    def ser_g1(p):
        return chr(G1_PREFIX_MASK | p['y_lsb']) + p['x']

    @staticmethod
    def ser_g2(p):
        return chr(G2_PREFIX_MASK | p['y_gt']) + p['x']

    def serialize(self):
        r = ""
        r += ZCProof.ser_g1(self.g_A)
        r += ZCProof.ser_g1(self.g_A_prime)
        r += ZCProof.ser_g2(self.g_B)
        r += ZCProof.ser_g1(self.g_B_prime)
        r += ZCProof.ser_g1(self.g_C)
        r += ZCProof.ser_g1(self.g_C_prime)
        r += ZCProof.ser_g1(self.g_K)
        r += ZCProof.ser_g1(self.g_H)
        return r

    def __repr__(self):
        return "ZCProof(g_A=%s g_A_prime=%s g_B=%s g_B_prime=%s g_C=%s g_C_prime=%s g_K=%s g_H=%s)" \
               % (repr(self.g_A), repr(self.g_A_prime),
                  repr(self.g_B), repr(self.g_B_prime),
                  repr(self.g_C), repr(self.g_C_prime),
                  repr(self.g_K), repr(self.g_H))


ZC_NUM_JS_INPUTS = 2
ZC_NUM_JS_OUTPUTS = 2

ZC_NOTEPLAINTEXT_LEADING = 1
ZC_V_SIZE = 8
ZC_RHO_SIZE = 32
ZC_R_SIZE = 32
ZC_MEMO_SIZE = 512

ZC_NOTEPLAINTEXT_SIZE = (
        ZC_NOTEPLAINTEXT_LEADING +
        ZC_V_SIZE +
        ZC_RHO_SIZE +
        ZC_R_SIZE +
        ZC_MEMO_SIZE
)

NOTEENCRYPTION_AUTH_BYTES = 16

ZC_NOTECIPHERTEXT_SIZE = (
        ZC_NOTEPLAINTEXT_SIZE +
        NOTEENCRYPTION_AUTH_BYTES
)

class JSDescription(object):
    def __init__(self):
        self.vpub_old = 0
        self.vpub_new = 0
        self.anchor = 0
        self.nullifiers = [0] * ZC_NUM_JS_INPUTS
        self.commitments = [0] * ZC_NUM_JS_OUTPUTS
        self.onetimePubKey = 0
        self.randomSeed = 0
        self.macs = [0] * ZC_NUM_JS_INPUTS
        self.proof = None
        self.ciphertexts = [None] * ZC_NUM_JS_OUTPUTS

    def deserialize(self, f):
        self.vpub_old = struct.unpack("<q", f.read(8))[0]
        self.vpub_new = struct.unpack("<q", f.read(8))[0]
        self.anchor = deser_uint256(f)

        self.nullifiers = []
        for i in range(ZC_NUM_JS_INPUTS):
            self.nullifiers.append(deser_uint256(f))

        self.commitments = []
        for i in range(ZC_NUM_JS_OUTPUTS):
            self.commitments.append(deser_uint256(f))

        self.onetimePubKey = deser_uint256(f)
        self.randomSeed = deser_uint256(f)

        self.macs = []
        for i in range(ZC_NUM_JS_INPUTS):
            self.macs.append(deser_uint256(f))

        self.proof = ZCProof()
        self.proof.deserialize(f)

        self.ciphertexts = []
        for i in range(ZC_NUM_JS_OUTPUTS):
            self.ciphertexts.append(f.read(ZC_NOTECIPHERTEXT_SIZE))

    def serialize(self):
        r = ""
        r += struct.pack("<q", self.vpub_old)
        r += struct.pack("<q", self.vpub_new)
        r += ser_uint256(self.anchor)
        for i in range(ZC_NUM_JS_INPUTS):
            r += ser_uint256(self.nullifiers[i])
        for i in range(ZC_NUM_JS_OUTPUTS):
            r += ser_uint256(self.commitments[i])
        r += ser_uint256(self.onetimePubKey)
        r += ser_uint256(self.randomSeed)
        for i in range(ZC_NUM_JS_INPUTS):
            r += ser_uint256(self.macs[i])
        r += self.proof.serialize()
        for i in range(ZC_NUM_JS_OUTPUTS):
            r += ser_uint256(self.ciphertexts[i])
        return r

    def __repr__(self):
        return "JSDescription(vpub_old=%i.%08i vpub_new=%i.%08i anchor=%064x onetimePubKey=%064x randomSeed=%064x proof=%s)" \
               % (self.vpub_old, self.vpub_new, self.anchor,
                  self.onetimePubKey, self.randomSeed, repr(self.proof))

