import hmac
import hashlib
from address import *

def hmac_sha256(keyhex, msghex):
    """Computes HMAC-SHA256 using hex inputs and returns a hex-encoded result."""
    key = bytes.fromhex(keyhex)  # Convert hex string to bytes
    msg = bytes.fromhex(msghex)  # Convert hex string to bytes
    hmac_result = hmac.new(key, msg, hashlib.sha256).hexdigest()  # Compute HMAC-SHA256 and return hex
    return hmac_result


def sha256(hexval) :
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

def chain(X, i, s, pk_seed, adrs_hex, showdebug=False):
    """chain unrolled"""
    # adrs is in hex, get object
    o = Adrs.fromHex(adrs_hex)
    for hashaddr in range(i, s):
        #print(f"hashaddr={hashaddr}")
        adrs_hex = o.setHashAddress(hashaddr).toHex()
        if showdebug: print(f"adrs={adrs_hex}")
        X = sha256(BlockPad(pk_seed) + adrs_hex + X)[:32]
        if showdebug: print(f"F({hashaddr})=", X)
    return X

def hash_pairwise(hashes, adrs, pk_seed, startidx=0, showdebug=False):

    n = len(hashes) // 2
    out = ['' for x in range(n)]
    for i in range(n):
        adrs.setTreeIndex(startidx + i)
        if showdebug: print(f"ADRS={adrs.toHex()}")
        h = sha256(BlockPad(pk_seed) + adrs.toHex() + hashes[2 * i] + hashes[2 * i + 1])[:32]
        out[i] = h
    return out


def hash_root(hashes, adrs, pk_seed, startidx=0, showdebug=False):

    # Leaves are at tree height 0
    treeht = 0
    while len(hashes) > 1:
        treeht += 1
        adrs.setTreeHeight(treeht)
        startidx //= 2
        hashes = hash_pairwise(hashes, adrs, pk_seed, startidx, showdebug)
        if showdebug: print(hashes)
    return hashes[0]


def authpath(leaves, adrs, pk_seed, leaf_idx, startidx=0, showdebug=False):

    auth = []
    treeht = 0
    i = leaf_idx
    while len(leaves) > 1:
        # Get hash value we want at current level
        y = i ^ 1
        auth.append(leaves[y])
        treeht += 1
        i //= 2
        startidx //= 2
        adrs.setTreeHeight(treeht)
        leaves = hash_pairwise(leaves, adrs, pk_seed, startidx, showdebug)
    return auth

if __name__ == '__main__':
    # Basic SHA256 with hex-encoded input
    h = sha256('616263')  # 'abc' in hex
    print(h)
    # ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    assert (h == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    h = sha256('')  # hash of empty string
    print(h)
    # e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert (h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    # HMAC with hex-encoded input RFC 4231
    h = hmac_sha256("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265")
    print(h)
    # b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    assert (h == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

    # MGF1_SHA256
    h = mgf1_sha256('3b5c056af3ebba70d4c805380420585562b32410a778f558ff951252407647e3', 34)
    print(h)
    # 5b7eb772aecf04c74af07d9d9c1c1f8d3a90dcda00d5bab1dc28daecdc86eb87611e
    assert (h == "5b7eb772aecf04c74af07d9d9c1c1f8d3a90dcda00d5bab1dc28daecdc86eb87611e")

    h = mgf1_sha256('', 16)
    print(h)
    # df3f619804a92fdb4057192dc43dd748
    assert (h == "df3f619804a92fdb4057192dc43dd748")

    # Compute the root node of Merkle tree using H
    PKseed = 'B505D7CFAD1B497499323C8686325E47'
    # Start with 8 leaf values in array
    leaves = ['505df0061b7e0041c8501bc5030ad439',
              '7bd5deb67217d33505043e204d88f687',
              '03b03bb327c9b48beab7722c4d5eb906',
              'fa1ef7c928518b1afdebddd1b83a3b66',
              '44b4dad150fdf64b6aa7fab1aea016e6',
              '0913211acf332a24629915d1b8226ff2',
              'a8fca106e9c1263dda280988f59f13e2',
              '84035916aba8e0b92f73364d4bb50a18']
    # Top-most tree out of 22, layer=21
    adrs = Adrs(Adrs.TREE, layer=0x15)
    root = hash_root(leaves, adrs, PKseed)
    print(f"root={root}")
    print(f"OK  =4fdfa42840c84b1ddd0ea5ce46482020")

    msg = 'WE ARE TRYING TO GENERATE A SPHINCSPLUS SIGNATURE FOR THIS MESSAGE'
    print(len(msg))