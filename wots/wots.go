package wots

import (
	"math"
	"../tweakable"
	"../address"
	"../parameters"
	"../util"
)

const (
	WOTS_HASH = 0
	WOTS_PK = 1
)

// Calculates the value of F iterated s times on X
func chain(X []byte, startIndex int, steps int, PKseed []byte, adrs *address.ADRS) []byte { //Replace ADRS with struct maybe
	if(steps == 0) {
		return X
	}
	if((startIndex + steps) > (parameters.W-1)) {
		return nil
	}

	tmp := chain(X, startIndex, steps - 1, PKseed, adrs)

	adrs.SetHashAddress(startIndex + steps - 1)

	hashFunc := tweakable.Sha256Tweak{}
	tmp = hashFunc.F(tweakable.Robust, PKseed, adrs, tmp) 

	return tmp
}

// WOTS+ private/secret key generation - NOT NEEDED FOR IMPLEMENTATION
func Wots_SKgen(SKseed []byte, adrs *address.ADRS) []byte {
	// Recalculating len parameter, as it cannot be stored as a const in parameters.go
	len1 := int(math.Ceil(8*parameters.N/math.Log2(parameters.W)))
	len2 := int(math.Floor(math.Log2(math.Ceil(8*parameters.N/math.Log2(parameters.W-1)))/math.Log2(parameters.W))+1)
	len := len1 + len2
	
	sk := make([]byte, len * parameters.N)

	hashFunc := tweakable.Sha256Tweak{}
	for	i := 0; i < len; i++ {
		adrs.SetChainAddress(i)
		adrs.SetHashAddress(0)
		copy(sk[i * parameters.N:], hashFunc.PRF(SKseed, adrs))
	}

	return sk
}

// WOTS+ public key generation
func Wots_PKgen(SKseed []byte, PKseed []byte, adrs *address.ADRS) []byte {
	// Recalculating len parameter, as it cannot be stored as a const in parameters.go
	len1 := int(math.Ceil(8*parameters.N/math.Log2(parameters.W)))
	len2 := int(math.Floor(math.Log2(math.Ceil(8*parameters.N/math.Log2(parameters.W-1)))/math.Log2(parameters.W))+1)
	len := len1 + len2

	//wotspkADRS := adrs // Make a copy of adrs
	wotspkADRS := new(address.ADRS)
	wotspkADRS.LayerAddress = adrs.LayerAddress
	wotspkADRS.TreeAddress = adrs.TreeAddress
	wotspkADRS.Type = adrs.Type
	wotspkADRS.KeyPairAddress = adrs.KeyPairAddress
	wotspkADRS.TreeHeight = adrs.TreeHeight
	wotspkADRS.TreeIndex = adrs.TreeIndex
	wotspkADRS.ChainAddress = adrs.ChainAddress
	wotspkADRS.HashAddress = adrs.HashAddress

	tmp := make([]byte, len * parameters.N)
	hashFunc := tweakable.Sha256Tweak{}

	for	i := 0; i < len; i++ {
		adrs.SetChainAddress(i)
		adrs.SetHashAddress(0)
		sk := hashFunc.PRF(SKseed, adrs)
		copy(tmp[i * parameters.N:], chain(sk, 0, parameters.W - 1, PKseed, adrs))
	}
	wotspkADRS.SetType(WOTS_PK)
	wotspkADRS.SetKeyPairAddress(adrs.GetKeyPairAddress())

	pk := make([]byte, len * parameters.N)
	pk = hashFunc.T_l(tweakable.Robust, PKseed, wotspkADRS, tmp)
	return pk
}

// Signs a message using WOTS+
func Wots_sign(message []byte, SKseed []byte, PKseed []byte, adrs *address.ADRS) []byte {
	// Recalculating len parameter, as it cannot be stored as a const in parameters.go
	len1 := int(math.Ceil(8*parameters.N/math.Log2(parameters.W)))
	len2 := int(math.Floor(math.Log2(math.Ceil(8*parameters.N/math.Log2(parameters.W-1)))/math.Log2(parameters.W))+1)

	len := len1 + len2

	csum := 0

	// Convert message to base w
	msg := util.Base_w(message, parameters.W, len1)

	for i := 0; i < len1; i++ {
		csum = csum + parameters.W - 1 - msg[i]
	}

	// convert csum to base w
	if int(math.Log2(parameters.W)) % 8 != 0 {		//Might be neccesary to convert result of Log2 to int with int(...)
		csum = csum << (8 - ((len2 * int(math.Log2(parameters.W))) % 8))
	}

	len2_bytes := uint(math.Ceil( ( float64(len2) * math.Log2(parameters.W) ) / 8 ))
	msg = append(msg, util.Base_w(util.ToByte(uint32(csum), len2_bytes), parameters.W, len2)...)
	hashFunc := tweakable.Sha256Tweak{}

	sig := make([]byte, len * parameters.N)

	for	i := 0; i < len; i++ {
		adrs.SetChainAddress(i)
		adrs.SetHashAddress(0)
		sk := hashFunc.PRF(SKseed, adrs)
		copy(sig[i * parameters.N:], chain(sk, 0, msg[i], PKseed, adrs))
	}

	return sig
}

// Finds pk from signature, for verification
func Wots_pkFromSig(signature []byte, message []byte, PKseed []byte, adrs *address.ADRS) []byte {
	// Recalculating len parameter, as it cannot be stored as a const in parameters.go
	len1 := int(math.Ceil(8*parameters.N/math.Log2(parameters.W)))
	len2 := int(math.Floor(math.Log2(math.Ceil(8*parameters.N/math.Log2(parameters.W-1)))/math.Log2(parameters.W))+1)
	len := len1 + len2
	
	csum := 0

	//wotspkADRS := adrs // Make a copy of adrs
	wotspkADRS := new(address.ADRS)
	wotspkADRS.LayerAddress = adrs.LayerAddress
	wotspkADRS.TreeAddress = adrs.TreeAddress
	wotspkADRS.Type = adrs.Type
	wotspkADRS.KeyPairAddress = adrs.KeyPairAddress
	wotspkADRS.TreeHeight = adrs.TreeHeight
	wotspkADRS.TreeIndex = adrs.TreeIndex
	wotspkADRS.ChainAddress = adrs.ChainAddress
	wotspkADRS.HashAddress = adrs.HashAddress

	// convert message to base w
	msg := util.Base_w(message, parameters.W, len1)

	// compute checksum
	for i := 0; i < len1; i++ {
		csum = csum + parameters.W - 1 - msg[i];
	}

	csum = csum << (8 - ((len2*int(math.Log2(parameters.W)))% 8))
	len2_bytes := int(math.Ceil( ( float64(len2) * math.Log2(parameters.W) ) / 8 ))
	msg = append(msg, util.Base_w(util.ToByte(uint32(csum), uint(len2_bytes)), parameters.W, len2)...)
	hashFunc := tweakable.Sha256Tweak{}
	tmp := make([]byte, len * parameters.N)
	
	for	i := 0; i < len; i++ {
		adrs.SetChainAddress(i)
		copy(tmp[i * parameters.N:], chain(signature[i * parameters.N:(i+1) * parameters.N], msg[i], parameters.W - 1 - msg[i], PKseed, adrs)) // IS THIS CORRECT??
	}

	wotspkADRS.SetType(WOTS_PK)
	wotspkADRS.SetKeyPairAddress(adrs.GetKeyPairAddress())
	
	pk_sig := hashFunc.T_l(tweakable.Robust, PKseed, wotspkADRS, tmp)
	return pk_sig
}