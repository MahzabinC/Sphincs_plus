import hmac
import hashlib

def hmac_sha256(keyhex, msghex):
    """Computes HMAC-SHA256 using hex inputs and returns a hex-encoded result."""
    key = bytes.fromhex(keyhex)  # Convert hex string to bytes
    msg = bytes.fromhex(msghex)  # Convert hex string to bytes
    hmac_result = hmac.new(key, msg, hashlib.sha256).hexdigest()  # Compute HMAC-SHA256 and return hex
    return hmac_result


def sha256(hexval: str) -> str:
    """Computes the SHA-256 hash of a hex-encoded value and returns the result as a hex string."""
    # Convert hex string to bytes
    byte_data = bytes.fromhex(hexval)
    # Compute SHA-256 hash
    hash_result = hashlib.sha256(byte_data).digest()
    # Convert the hash result to a hex string
    return hash_result.hex()


def mgf1_sha256(msghex: str, mlen: int) -> str:
    msg_bytes = bytes.fromhex(msghex)  # Convert hex input to bytes
    mask = bytearray()  # Placeholder for the output mask
    counter = 0  # 4-byte counter for MGF1

    while len(mask) < mlen:
        # Compute SHA-256 of (msg || counter)
        counter_bytes = counter.to_bytes(4, byteorder="big")  # Convert counter to 4-byte big-endian
        digest = hashlib.sha256(msg_bytes + counter_bytes).digest()  # SHA-256 hash
        mask.extend(digest)  # Append to mask
        counter += 1  # Increment counter

    return mask[:mlen].hex()  # Truncate and return as lowercase hex string

def BlockPad(PKseed):
    # Pad PK.seed to 64 bytes with zeros (NB in hex)
    return PKseed + "0" * (128 - len(PKseed))

# Example usage
msghex = "48656c6c6f20576f726c64"  # "Hello World" in hex
keyhex = "6b6579"  # "key" in hex
print(hmac_sha256(msghex, keyhex))  # Equivalent to pki.Hmac.hex_from_hex(msghex, keyhex, pki.Hmac.Alg.SHA256)