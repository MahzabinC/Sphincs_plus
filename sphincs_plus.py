from fors import *
from wots import *
import re

SPX_DGST_BYTES=34
SPX_FORS_TREES = 33
SPX_FORS_HEIGHT = 6
t = 64
w = 16
SPX_WOTS_LEN = 35
SPX_TREE_HEIGHT = 22


DEBUG=False

def to_33_byte_hex(input_str):
    data = input_str.encode('utf-8')  # Convert to bytes
    padded = data.ljust(33, b'\x00')[:33]  # Pad or truncate to 33 bytes
    return padded.hex()
#Seed for private key
pk_seed = 'B505D7CFAD1B497499323C8686325E47'
pk_root = '4FDFA42840C84B1DDD0EA5CE46482020'
sk_seed = '7C9935A0B07694AA0C6D10E4DB6B1ADD'
SK_prf = '2fd81a25ccb148032dcd739936737f2d'
msg = to_33_byte_hex('hello there')
optrand = '33b3c07507e4201748494d832b6ee2a6'
expected_hash = 'ea2bef5299332943d7301a883aa6c1caba08975b7924ed581709b5b1c88beaad'

print(f"About to compute SPHINCS+ signature for {msg}...")

# Start composing the signature as a hex-encoded string with line breaks and comments
sig = ""

# Compute the randomizer R of 16 bytes using hex strings
R = compute_randomizer(SK_prf, optrand, msg)

sig += R + " # R\n"

# Compute H_msg from the message, public key and randomizer.
h_msg= compute_h_msg(R,pk_seed,pk_root,msg,34)
# Split into mhash (25 bytes), tree address (8 bytes) and idx_leaf (1 byte)
mhash, tree_addr, leaf_index = split_h_msg(h_msg)
# Interpret 25-byte mhash as 33 * 6-bit unsigned integers.
indices= message_to_indices(mhash,SPX_FORS_TREES,SPX_FORS_HEIGHT)

# Compute all 33 FORS signature sk values using the indices
fors_sig_sk= compute_fors_sig_sk(sk_seed,tree_addr,leaf_index,indices,t,SPX_FORS_TREES)
roots, sig = compute_fors_sk_pk(sk_seed,pk_seed,tree_addr,leaf_index,SPX_FORS_TREES,t,indices,sig,fors_sig_sk)
# Compute the FORS public key given the roots of the k FORS trees.
fors_pk= compute_fors_pk(roots,tree_addr,leaf_index,pk_seed)


# Input FORS public key to first WOTS signature
wots_input = fors_pk
#print(f"wots input={wots_input}")
# Loop for each of 22 subtrees in the HT
for layer in range(SPX_TREE_HEIGHT):
    m = wots_chain(wots_input, False)
    #print(m)

    # Compute the next WOTS signature.
    # Set up ADRS object
    adrs = Adrs(Adrs.WOTS_HASH, layer=layer)
    adrs.setTreeAddress(tree_addr)
    adrs.setKeyPairAddress(leaf_index)
    # print(f"ADRS base={adrs.toHex()}")

    htsigs = []
    compute_ht_sig(sk_seed, pk_seed, SPX_WOTS_LEN, m, adrs, htsigs)

    # Output this ht_sig (560 bytes) to the signature value
    #print(f"htsigs={htsigs}")
    sig += htsigs[0] + format(f" # ht_sig[{layer}]\n")
    sig += "\n".join(htsigs[1:]) + "\n"

    leaves = []
    # Compute all leaves of subtree at this layer
    for this_leaf in range(8):
        adrs = Adrs(Adrs.WOTS_HASH, layer=layer)
        adrs.setTreeAddress(tree_addr)
        adrs.setKeyPairAddress(this_leaf)
        heads = ""  # concatenation of heads of WOTS+ chains
        for chainaddr in range(35):
            adrs.setChainAddress(chainaddr)
            adrs_hex = adrs.toHex()
            sk = sha256(sk_seed + adrs_hex)[:32] #PRF(SKseed, adrs_hex)
            pk = chain(sk, 0, w - 1, pk_seed, adrs_hex,
                       showdebug=(DEBUG and (chainaddr < 2 or chainaddr == 34)))
            #print(f"pk={pk}")
            heads += pk

        # for thash,
        wots_pk_adrs = Adrs(Adrs.WOTS_PK, layer=layer)
        wots_pk_adrs.setTreeAddress(tree_addr)
        wots_pk_adrs.setKeyPairAddress(this_leaf)
        wots_pk_addr_hex = wots_pk_adrs.toHex()
        #print(f"wots_pk_addr={wots_pk_addr_hex}")
        leaf = sha256(BlockPad(pk_seed) + wots_pk_addr_hex + heads)[:32] #T_len(PKseed, wots_pk_addr_hex, heads)
        #print(f"leaf[{leaf}]={leaf}")
        leaves.append(leaf)

    #print(leaves)

    # Compute the root node of Merkle tree using H
    # Start with 8 leaf values in array
    adrs = Adrs(Adrs.TREE, layer=layer)
    adrs.setTreeAddress(tree_addr)
    root = hash_root(leaves, adrs, pk_seed)

    # Compute the authentication path from leaf_idx
    auth = authpath(leaves, adrs, pk_seed, leaf_index)


    # Output this authpath to the signature value
    sig += auth[0] + format(f" # ht_auth_path[{layer}]\n")
    sig += "\n".join(auth[1:]) + "\n"

    # Set next wots_input to root and change tree_addr for next layer
    wots_input = root
    leaf_index = tree_addr & 0x7  # (2^3 - 1)
    tree_addr >>= 3
    # Loop for next higher subtree...

# At the end the final root value MUST equal PK.root
print(f"Final root={wots_input}")
print(f"Expecting ={pk_root}")
assert wots_input.lower() == pk_root.lower()

# Print out and check the signature
print(f"sig:\n{sig}")

print("sig lines =", sig.count('\n'), "(expecting 1068)")
# Strip sig string down to pure hex digits
sighex = sig
sighex = re.sub(r'\s+\#.*?$', '', sighex, flags=re.MULTILINE)

sighex = sighex.replace('\n', '')

print("sighex len =", len(sighex), "(expecting 17088 x 2 = 34176)")
# Compute SHA-256 of signature
hash_sig = sha256(sighex)
print(f"SHA256(sighex)={hash_sig}")

