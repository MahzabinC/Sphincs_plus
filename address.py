"""SPHINCS+ ADRS Class."""

"""Usage:
    from address import Adrs
    adrs = Adrs()
    adrs.setType(adrs.WOTS_HASH)
    print("adrs =", adrs.toHex())
    adrs = Adrs.fromHex("1528daecdc86eb87610300000002000000020000000d")

Format:
layer   treeaddr  type    word1    word2    word3
[1]          [8]   [1]      [4]      [4]      [4]
00 28daecdc86eb8761 03 00000006 00000000 0000001b
0  1                9  10       14       18  # byte offsets
0  2                18 20       28       36  # hex offsets

--------------------------------------------------------------------------
Type                    word1        word2      word3       Type constant      
-------------------------------------------------------------------------                 
0 WOTS+ hash addr       keypairaddr  chainaddr  hashaddr    WOTS_HASH
1 WOTS+ pub key compr   keypairaddr  0          0           WOTS_PK
2 Hash tree addr        0            tree ht    tree index  TREE
3 FORS tree addr        keypairaddr  tree ht    tree index  FORS_TREE  
4 FORS tree roots compr keypairaddr  0          0           FORS_ROOTS
"""


class Adrs:
    """Class for ADRS using 22-byte SHA-256 compressed address."""

    def __init__(self, adrs_type=0, layer=0, treeaddr=0, word1=0, word2=0, word3=0):
        self.adrs_type = adrs_type
        self.layer = layer
        self.treeaddr = int(treeaddr)
        # Last 3 words have different meanings depending on type (see table above)
        # so we use generic names
        self.word1 = word1
        self.word2 = word2
        self.word3 = word3

    # Type constants
    WOTS_HASH = 0
    WOTS_PK = 1
    TREE = 2
    FORS_TREE = 3
    FORS_ROOTS = 4

    def toHex(self):
        """Return 22-byte ADRS in hex format."""
        # Fix to ensure treeaddr is treated as a 64-bit number
        treeaddr_hex = format(self.treeaddr, f'x').zfill(16)
        return format(self.layer, f'02x') + treeaddr_hex \
            + format(self.adrs_type, f'02x') + format(self.word1, f'08x') \
            + format(self.word2, f'08x') + format(self.word3, f'08x')

    def toHexSP(self):
        """Return ADRS in hex format with spaces."""
        treeaddr_hex = format(self.treeaddr, f'x').zfill(16)
        return format(self.layer, f'02x') + ' ' + treeaddr_hex + ' ' \
            + format(self.adrs_type, f'02x') + ' ' + format(self.word1, f'08x') \
            + ' ' + format(self.word2, f'08x') + ' ' + format(self.word3, f'08x')

    @classmethod
    def fromHex(cls, hexval):
        """Read in address in hex to new Adrs object"""
        layer = int(hexval[:2], 16)
        treeaddr = int(hexval[2:18], 16)
        adrs_type = int(hexval[18:20], 16)
        word1 = int(hexval[20:28], 16)
        word2 = int(hexval[28:36], 16)
        word3 = int(hexval[36:44], 16)
        return cls(adrs_type, layer, treeaddr, word1, word2, word3)

    def setType(self, adrs_type):
        self.adrs_type = adrs_type
        # Changing type initializes the subsequent 3 words to 0
        self.word1 = 0
        self.word2 = 0
        self.word3 = 0
        return self

    def setKeyPairAddress(self, kpa):
        self.word1 = kpa
        return self

    def getKeyPairAddress(self):
        return self.word1

    def setTreeHeight(self, ht):
        self.word2 = ht
        return self

    def getTreeHeight(self):
        return self.word2

    def setTreeIndex(self, idx):
        self.word3 = idx
        return self

    def getTreeIndex(self):
        return self.word3

    def setChainAddress(self, ca):
        self.word2 = ca
        return self

    def setHashAddress(self, ha):
        self.word3 = ha
        return self

    def setLayerAddress(self, la):
        self.layer = la
        return self

    def setTreeAddress(self, ta):
        self.treeaddr = int(ta)
        return self


if __name__ == '__main__':
    # Create a new ADRS object
    adrs = Adrs()
    print(adrs.toHex())

    adrs = Adrs(3, 0, 0x28daecdc86eb8761, word3=27, word1=6)
    print(adrs.toHex())
    adrs.setType(4)
    print(adrs.toHex())
    adrs.setType(adrs.WOTS_HASH)
    print(adrs.toHex())
    hexval = adrs.toHex()
    print(hexval)
    print(adrs.fromHex(hexval).toHex())
    hexval = "1528daecdc86eb87610300000001000000030000000e"
    print(hexval)
    print(adrs.fromHex(hexval).toHex())
    adrs = adrs.fromHex(hexval)
    adrs.setType(adrs.TREE)
    print(adrs.toHex())
    adrs = Adrs.fromHex("1528daecdc86eb87610300000002000000020000000d")
    print(adrs.toHex())
    print(adrs.toHexSP())