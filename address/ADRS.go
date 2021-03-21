package address

type ADRS struct {
    LayerAddress [4]byte
	TreeAddress [12]byte
	Type [4]byte
	KeyPairAddress [4]byte
	TreeHeight [4]byte
	TreeIndex [4]byte
	ChainAddress [4]byte
	HashAddress [4]byte
}