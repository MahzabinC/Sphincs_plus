import hashlib
import os
import math
from address import *
from meow import *
m = 8  # Message length in bits
w = 4  # Winternitz parameter
l1 = math.ceil(m / math.log2(w))  # Number of hash chains
l2 = math.floor(math.log2(l1 * (w - 1)) / math.log2(w)) + 1  # Checksum length
l = l1 + l2  # Total chains
SEED_SIZE = 32  # Security parameter

# Hash function
HASH_FUNC = hashlib.sha256

def hash_function(data):
    return HASH_FUNC(data).digest()


# For extra layer of security
def xor_byte(a, b):
    #Perform bitwise XOR on two byte sequences.
    return bytes(x ^ y for x, y in zip(a, b))


# Chaining function with XOR-based masking
def hash_chain(value, i, max_steps, randomization_element):
    for step in range(i, max_steps):
        value = hash_function(xor_byte(value, randomization_element[step]))  # XOR, then hash
    return value

# Key Generation
def wots_key_generate():
    private_key = [os.urandom(SEED_SIZE) for _ in range(l)]
    r = [os.urandom(SEED_SIZE) for _ in range(w - 1)]  # Randomization elements
    public_key = [hash_chain(sk, 0, w - 1, r) for sk in private_key]
    pk_hash = hash_function(b"".join(public_key))
    return private_key, r, public_key, pk_hash

# Convert integer to base-w representation
def to_base_w(message, length):
    if isinstance(message, str):
        message = int(message, 16)  # Convert hex string to integer
    elif isinstance(message, bytes):
        message = int.from_bytes(message, "big")  # Convert bytes to integer

    digits = []
    for _ in range(length):
        digits.append(message % w)
        message //= w
    return digits[::-1]  # Reverse for correct order

# Compute checksum
def compute_checksum(message_segments):
    csum = sum((w - 1 - xi) for xi in message_segments)
    csum &= 0xfff  # truncate to 12 bits
    return csum

# getting full message in hex
def wots_fm(msghex):
    msg = [int(x, 16) for x in msghex]
    # print(msg)
    # Compute csum
    csum = compute_checksum(msg)
    msg.append((csum >> 8) & 0xF)
    msg.append((csum >> 4) & 0xF)
    msg.append((csum >> 0) & 0xF)
    return msg


# For sphincs+
def compute_ht_sig(sk_seed,pk_seed,tree_addr,leaf_index,SPX_WOTS_LEN,l,m):
    # Set up ADRS object
    adrs = Adrs(Adrs.WOTS_HASH, layer=l)
    adrs.setTreeAddress(tree_addr)
    adrs.setKeyPairAddress(leaf_index)
    print(f"ADRS base={adrs.toHex()}")

    ht_sigs = []
    for idx in range(SPX_WOTS_LEN):  # 35
        print(f"Generate WOTS+ private key for i = {idx}")
        adrs.setChainAddress(idx)
        adrs_c = adrs.toHex()
        print(f"ADRS={adrs_c}")
        sk = sha256(sk_seed + adrs_c)[:32]
        print(f"sk={sk}")

        # Compute F^m_i(sk)
        mi = m[idx]
        print(f"m[{idx}]={mi}")
        x = sk
        adrs_ht = Adrs.fromHex(adrs.toHex())
        for i in range(mi):
            adrs_ht.setHashAddress(i)
            adrs_c = adrs_ht.toHex()
            print(f"i={i} ADRS={adrs_c}")
            print(f"in={x}")
            x = sha256(BlockPad(pk_seed) + adrs_c + x)[:32]
            print(f"F(PK.seed, ADRS, in)={x}")

        print(f"ht_sig:{x}")
        ht_sigs.append(x)
    return ht_sigs

def chain(X, i, s, pk_seed, adrs_hex, showdebug=False):
    """chain unrolled"""
    # adrs is in hex, get object
    o = Adrs.fromHex(adrs_hex)
    for hashaddr in range(i, s):
        #print(f"hashaddr={hashaddr}")
        adrs_hex = o.setHashAddress(hashaddr).toHex()
        if showdebug: print(f"adrs={adrs_hex}")
        X = sha256(BlockPad(pk_seed)+adrs_hex+X)[:32]
        if showdebug: print(f"F({hashaddr})=", X)
    return X

# Signing a message
def wots_sign(message, private_key, randomization_element):
    message_segments = to_base_w(message, l1)
    checksum = compute_checksum(message_segments)
    full_message = message_segments + checksum

    print(f"Message Segments (Signing): {message_segments}")
    print(f"Checksum (Signing): {checksum}")

    signature = [hash_chain(private_key[i], 0, xi, randomization_element) for i, xi in enumerate(full_message)]
    return signature

# Verifying a signature
def wots_verify(message, signature, randomization_element, public_key, pk_hash):
    message_segments = to_base_w(message, l1)
    checksum = compute_checksum(message_segments)
    full_message = message_segments + checksum

    print(f"Message Segments (Verification): {message_segments}")
    print(f"Checksum (Verification): {checksum}")
    print(f"Full Message (Verification): {full_message}")

    computed_pk = [hash_chain(sig_i, bi, w - 1, randomization_element) for sig_i, bi in zip(signature, full_message)]
    computed_pk_hash = hash_function(b"".join(computed_pk))

    print(f"Computed PK Hash: {computed_pk_hash.hex()}")
    print(f"Original PK Hash: {pk_hash.hex()}")

    return computed_pk_hash == pk_hash

# Example Usage
# private_key, r, public_key, pk_hash = wots_key_generate()
# message = 42  # Example message
# signature = wots_sign(message, private_key, r)
# print("WOTS+ Signature Verified:", wots_verify(message, signature, r, public_key, pk_hash))
