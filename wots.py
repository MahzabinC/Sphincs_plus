import os
import math
from address import *
from meow import *
m = 128  # Message length in bits
w = 16  # Winternitz parameter
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

def wots_chain(message_hex,show_csum=False):
    # Convert message to base-w digits
    msg_segments = to_base_w(message_hex, l1)

    # Compute checksum
    csum_value = compute_checksum(msg_segments)
    if show_csum:
        print(f"csum={csum_value:03x}")

    # Convert checksum to base-w digits
    csum_segments = to_base_w(csum_value, l2)

    # Combine base-w message and checksum
    full_message_segments = msg_segments + csum_segments
    return full_message_segments


# For sphincs+
def compute_ht_sig(sk_seed,pk_seed,SPX_WOTS_LEN,m,adrs,ht_sigs):
    for idx in range(SPX_WOTS_LEN):  # 35
        #print(f"Generate WOTS+ private key for i = {idx}")
        adrs.setChainAddress(idx)
        adrs_c = adrs.toHex()
        #print(f"ADRS={adrs_c}")
        #print(f"skseed={sk_seed}")
        sk = sha256(sk_seed + adrs_c)[:32]
        #print(f"sk={sk}")

        # Compute F^m_i(sk)
        mi = m[idx]
        #print(f"m[{idx}]={mi}")
        x = sk
        adrs_ht = Adrs.fromHex(adrs.toHex())
        for i in range(mi):
            adrs_ht.setHashAddress(i)
            adrs_c = adrs_ht.toHex()
            #print(f"i={i} ADRS={adrs_c}")
            #print(f"in={x}")
            x = sha256(BlockPad(pk_seed) + adrs_c + x)[:32]
            #print(f"F(PK.seed, ADRS, in)={x}")

        #print(f"ht_sig:{x}")
        ht_sigs.append(x)


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
