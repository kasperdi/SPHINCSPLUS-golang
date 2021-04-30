package wots

import (
	"math"
	"../address"
	"../parameters"
	"../util"
)

type WotsParams parameters.Parameters

// Calculates the value of F iterated s times on X
func (params *WotsParams) chain(X []byte, startIndex int, steps int, PKseed []byte, adrs *address.ADRS) []byte {
	if(steps == 0) {
		return X
	}
	if((startIndex + steps) > (params.W-1)) {
		return nil
	}

	tmp := make([]byte, params.N)
	copy(tmp, params.chain(X, startIndex, steps - 1, PKseed, adrs))

	adrs.SetHashAddress(startIndex + steps - 1)
	copy(tmp, params.Tweak.F(PKseed, adrs, tmp)) 

	return tmp
}

// WOTS+ public key generation
func (params *WotsParams) Wots_PKgen(SKseed []byte, PKseed []byte, adrs *address.ADRS) []byte {
	//wotspkADRS := adrs // Make a copy of adrs
	wotspkADRS := adrs.Copy()

	tmp := make([]byte, params.Len * params.N)

	for	i := 0; i < params.Len; i++ {
		adrs.SetChainAddress(i)
		adrs.SetHashAddress(0)
		sk := params.Tweak.PRF(SKseed, adrs)
		copy(tmp[i * params.N:], params.chain(sk, 0, params.W - 1, PKseed, adrs))
	}
	wotspkADRS.SetType(address.WOTS_PK)
	wotspkADRS.SetKeyPairAddress(adrs.GetKeyPairAddress())

	pk := make([]byte, params.Len * params.N)
	pk = params.Tweak.T_l(PKseed, wotspkADRS, tmp)
	return pk
}

// Signs a message using WOTS+
func (params *WotsParams) Wots_sign(message []byte, SKseed []byte, PKseed []byte, adrs *address.ADRS) []byte {
	csum := 0

	// Convert message to base w
	msg := util.Base_w(message, params.W, params.Len1)

	for i := 0; i < params.Len1; i++ {
		csum = csum + params.W - 1 - msg[i]
	}

	// convert csum to base w
	if int(math.Log2(float64(params.W))) % 8 != 0 {
		csum = csum << (8 - ((params.Len2 * int(math.Log2(float64(params.W)))) % 8))
	}

	len2_bytes := int(math.Ceil( ( float64(params.Len2) * math.Log2(float64(params.W)) ) / 8 ))
	msg = append(msg, util.Base_w(util.ToByte2(csum, len2_bytes), params.W, params.Len2)...)

	sig := make([]byte, params.Len * params.N)

	for	i := 0; i < params.Len; i++ {
		adrs.SetChainAddress(i)
		adrs.SetHashAddress(0)
		sk := params.Tweak.PRF(SKseed, adrs)
		copy(sig[i * params.N:], params.chain(sk, 0, msg[i], PKseed, adrs))
	}

	return sig
}

// Finds pk from signature, for verification
func (params *WotsParams) Wots_pkFromSig(signature []byte, message []byte, PKseed []byte, adrs *address.ADRS) []byte {
	csum := 0

	//wotspkADRS := adrs // Make a copy of adrs
	wotspkADRS := adrs.Copy()

	// convert message to base w
	msg := util.Base_w(message, params.W, params.Len1)

	// compute checksum
	for i := 0; i < params.Len1; i++ {
		csum = csum + params.W - 1 - msg[i];
	}

	csum = csum << (8 - ((params.Len2*int(math.Log2(float64(params.W))))% 8))
	len2_bytes := int(math.Ceil( ( float64(params.Len2) * math.Log2(float64(params.W)) ) / 8 ))
	msg = append(msg, util.Base_w(util.ToByte2(csum, len2_bytes), params.W, params.Len2)...)

	tmp := make([]byte, params.Len * params.N)
	
	for	i := 0; i < params.Len; i++ {
		adrs.SetChainAddress(i)
		copy(tmp[i * params.N:], params.chain(signature[i * params.N:(i+1) * params.N], msg[i], params.W - 1 - msg[i], PKseed, adrs))
	}

	wotspkADRS.SetType(address.WOTS_PK)
	wotspkADRS.SetKeyPairAddress(adrs.GetKeyPairAddress())
	
	pk_sig := params.Tweak.T_l(PKseed, wotspkADRS, tmp)
	return pk_sig
}