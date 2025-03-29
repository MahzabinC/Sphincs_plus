from address import Adrs
from meow import *



def compute_randomizer(sk_prf, optrand, message):
    """Computes the randomizer R"""
    r = hmac_sha256(sk_prf, optrand + message)
    return r[:32]


def compute_h_msg(R, pk_seed, pk_root, message, output_len: int = 34):
    """Computes h_msg using sha256 and mgf1."""
    h = sha256(R + pk_seed + pk_root + message)
    return mgf1_sha256(h, output_len)


def split_h_msg(h_msg: bytes):
    """Splits h_msg into message digest, tree address, and leaf index."""
    mhash = h_msg[:50]  # First 25 bytes
    tree_addr = int(h_msg[50:66], 16) & 0x7fffffffffffffff  # 63 bits
    leaf_index = int(h_msg[66:68],16) & 0x7  # 3-bit leaf index
    return mhash, tree_addr, leaf_index


def message_to_indices(mhash, fors_trees, fors_height):
    """Interprets 25-byte mhash as 33 × 6-bit unsigned integers."""
    indices = [0]*fors_trees
    bitstream = bytes.fromhex(mhash)
    offset=0
    for i in range(fors_trees):
        indices[i]=0
        for j in range(fors_height):
            indices[i] ^= ((bitstream[offset >> 3] >> (offset & 0x7)) & 0x1) << j
            offset += 1
    return indices

def compute_fors_sig_sk(sk_seed, tree_addr,leaf_index,indices,t, fors_tree) :
    if isinstance(indices, int):  # Convert integer to a list if needed
        indices = [indices] * fors_tree
    fors_sig_sk=[]
    adrs = Adrs(Adrs.FORS_TREE, layer=0)
    adrs.setTreeAddress(tree_addr)
    adrs.setKeyPairAddress(leaf_index)
    for i in range(fors_tree):
        treeindex = i * t + indices[i]
        adrs.setTreeIndex(treeindex)
        print(f"ADRS={adrs.toHex()}")
        sk = sha256(sk_seed + adrs.toHex())[:32]
        print(f"fors_sig_sk[{i}]={sk}")
        fors_sig_sk.append(sk)
    return fors_sig_sk

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


def compute_fors_sk_pk(sk_seed: bytes,pk_seed: bytes,tree_addr,leaf_index,fors_trees: int, t: int,indices,sig,fors_sig_sk) :
    """Computes the FORS secret key """
    # Compute all 33 FORS signature sk values
    roots=[]
    for i in range(fors_trees):
        adrs = Adrs(Adrs.FORS_TREE, layer=0)
        adrs.setTreeAddress(tree_addr)
        adrs.setKeyPairAddress(leaf_index)
        leaves = []
        for j in range(t):
            treeindex = i * t + j
            adrs.setTreeIndex(treeindex)
            print(f"ADRS={adrs.toHex()}")
            sk = sha256(sk_seed + adrs.toHex())[:32]
            print(f"fors_sk[{i}][{j}]={sk}")
            pk = sha256(BlockPad(pk_seed) + adrs.toHex() + sk)[:32]
            print(f"fors_pk[{i}][{j}]={pk}")
            leaves.append(pk)
        # Compute the root value for this FORS tree
        adrs = Adrs(Adrs.FORS_TREE, layer=0)
        adrs.setTreeAddress(tree_addr)
        adrs.setKeyPairAddress(leaf_index)
        print(f"ADRS={adrs.toHex()}")
        root = hash_root(leaves, adrs, pk_seed, i * t)
        print(f"root[{i}]={root}")
        roots.append(root)
        # and the authpath for indices[i]
        idx = indices[i]
        print(f"i={i} idx={idx}")
        auth = authpath(leaves, adrs, pk_seed, idx, i * t)
        print(f"fors_auth_path[{i}]:")
        [print(a) for a in auth]
        # Output the sig_sk and authpath to the signature value
        sig += fors_sig_sk[i] + format(f" # fors_sig_sk[{i}]\n")
        sig += auth[0] + format(f" # fors_auth_path[{i}]\n")
        sig += "\n".join(auth[1:]) + "\n"

    return roots, sig

# Compute the FORS public key given the roots of the k FORS trees.
def compute_fors_pk(roots,tree_addr,leaf_index,pk_seed):
    adrs = Adrs(Adrs.FORS_TREE, layer=0)
    adrs.setTreeAddress(tree_addr)
    adrs.setKeyPairAddress(leaf_index)
    print(f"ADRS={adrs.toHex()}")
    fors_pk = sha256(BlockPad(pk_seed) + adrs.toHex() + "".join(roots))[:32]
    print(f"fors_pk[{leaf_index}]={fors_pk}")
    return fors_pk



