package WOTSplus
//import "math"
import "math/big"
	
// Parameters for WOTS+
const ( 
	n = 32
	w = 4
	// len1 kan findes ved: math.Ceil(8*n/math.Log2(w))
	// len2 kan findes ved: math.Floor(math.Log2(math.Ceil(8*n/math.Log2(w-1)))/math.Log2(w))+1
	// len kan findes ved: len1 + len2
)

type ADRS struct {
    LayerAddress [4]byte
	TreeAddress [12]byte
	Type int32
	KeyPairAddress [4]byte
	TreeHeight int32
	TreeIndex int32
	ChainAddress [4]byte
	HashAddress int32
}

// Setter method for ADRS
func (address *ADRS) setHashAddress(newAddress int32) {
	address.HashAddress = newAddress
}

// Calculates the value of F iterated s times on X
func chain(X []byte, startIndex int, steps int, PKseed *big.Int, address *ADRS) []byte { //Replace ADRS with struct maybe
	if(x == 0) {
		return X
	}
	if((i+s) > (w-1)) {
		return nil
	}
	tmp [n]byte = chain(X, i, s - 1, PKseed, address)

	address.setHashAddress(i + s - 1)
	tmp = F(PKseed, address, tmp)
	return tmp
}

func Wots_SKgen(SKseed int, address *ADRS) []byte {
	return nil
}

func Wots_PKgen(SKseed int, PKseed int, address *ADRS) []byte {
	return nil
}

func Wots_sign(message []byte, SKseed int, PKseed int, address *ADRS) []byte {
	return nil
}

func Wots_pkFromSig(signature []byte, message []byte, PKseed int, address *ADRS) []byte {
	return nil
}