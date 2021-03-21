package WOTSplus
//import "math"
import "math/big"
/* import "../tweakable" */
import "../address"
import "../parameters"

// Setter method for ADRS
func (address *ADRS) setHashAddress(newAddress int32) {
	address.HashAddress = newAddress
}

// Calculates the value of F iterated s times on X
func chain(X []byte, startIndex int, steps int, PKseed *big.Int, adrs *address.ADRS) []byte { //Replace ADRS with struct maybe
	if(steps == 0) {
		return X
	}
	if((startIndex + steps) > (parameters.W-1)) {
		return nil
	}

	var tmp [n]byte // Change to use := ?
	tmp = chain(X, startIndex, steps - 1, PKseed, adrs)

	adrs.setHashAddress(startIndex + steps - 1)
	tmp = F(PKseed, address, tmp)
	return tmp
}

func Wots_SKgen(SKseed int, adrs *address.ADRS) []byte {
	return nil
}

func Wots_PKgen(SKseed int, PKseed int, adrs *address.ADRS) []byte {
	return nil
}

func Wots_sign(message []byte, SKseed int, PKseed int, adrs *address.ADRS) []byte {
	return nil
}

func Wots_pkFromSig(signature []byte, message []byte, PKseed int, adrs *address.ADRS) []byte {
	return nil
}