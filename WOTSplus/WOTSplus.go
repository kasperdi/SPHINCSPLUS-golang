package WOTSplus
//import "math"
import "math/big"
import "../tweakable"
	
// Parameters for WOTS+
const ( 
	n = 32
	w = 4
	// len1 kan findes ved: math.Ceil(8*n/math.Log2(w))
	// len2 kan findes ved: math.Floor(math.Log2(math.Ceil(8*n/math.Log2(w-1)))/math.Log2(w))+1
	// len kan findes ved: len1 + len2
)

// Setter method for ADRS
func (address *ADRS) setHashAddress(newAddress int32) {
	address.HashAddress = newAddress
}

// Calculates the value of F iterated s times on X
func chain(X []byte, startIndex int, steps int, PKseed *big.Int, address *ADRS) []byte { //Replace ADRS with struct maybe
	if(steps == 0) {
		return X
	}
	if((startIndex + steps) > (w-1)) {
		return nil
	}

	var tmp [n]byte // Change to use := ?
	tmp = chain(X, startIndex, steps - 1, PKseed, address)

	address.setHashAddress(startIndex + steps - 1)
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