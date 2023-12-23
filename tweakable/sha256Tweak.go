package tweakable

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"

	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/util"
)

type Sha256Tweak struct {
	Variant             string
	MessageDigestLength int
	N                   int
}

// Keyed hash function Hmsg
func (h *Sha256Tweak) Hmsg(R []byte, PKseed []byte, PKroot []byte, M []byte) []byte {

	hash := sha256.New()
	hash.Write(R)
	hash.Write(PKseed)
	hash.Write(PKroot)
	hash.Write(M)
	hashedConc := hash.Sum(nil)
	bitmask := mgf1sha256(hashedConc, h.MessageDigestLength)
	return bitmask
}

// Pseudorandom function PRF
func (h *Sha256Tweak) PRF(SEED []byte, adrs *address.ADRS) []byte {
	compressedADRS := compressADRS(adrs)
	hash := sha256.New()
	hash.Write(SEED)
	hash.Write(compressedADRS)
	return hash.Sum(nil)[:h.N]
}

// Pseudorandom function PRFmsg
func (h *Sha256Tweak) PRFmsg(SKprf []byte, OptRand []byte, M []byte) []byte {
	mac := hmac.New(sha256.New, SKprf)
	mac.Write(OptRand)
	mac.Write(M)
	return mac.Sum(nil)[:h.N]
}

// Tweakable hash function F
func (h *Sha256Tweak) F(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	var M1 []byte
	compressedADRS := compressADRS(adrs)

	if h.Variant == Robust {
		bitmask := mgf1sha256(append(PKseed, compressedADRS...), len(tmp))
		M1 = make([]byte, len(tmp))
		_ = subtle.XORBytes(M1, tmp, bitmask)
	} else if h.Variant == Simple {
		M1 = tmp
	}

	bytes := make([]byte, 64-h.N)

	hash := sha256.New()
	hash.Write(PKseed)
	hash.Write(bytes)
	hash.Write(compressedADRS)
	hash.Write(M1)
	return hash.Sum(nil)[:h.N]
}

// Tweakable hash function H
func (h *Sha256Tweak) H(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	return h.F(PKseed, adrs, tmp)
}

// Tweakable hash function T_l
func (h *Sha256Tweak) T_l(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	return h.F(PKseed, adrs, tmp)
}

// Compresses ADRS into 22 bytes
func compressADRS(adrs *address.ADRS) []byte {
	ADRSc := make([]byte, 22)

	copy(ADRSc[0:1], adrs.LayerAddress[3:4])
	copy(ADRSc[1:9], adrs.TreeAddress[4:12])
	copy(ADRSc[9:10], adrs.Type[3:4])

	switch adrs.GetType() {
	case address.WOTS_HASH:
		copy(ADRSc[10:14], adrs.KeyPairAddress[:])
		copy(ADRSc[14:18], adrs.ChainAddress[:])
		copy(ADRSc[18:22], adrs.HashAddress[:])
	case address.WOTS_PK:
		copy(ADRSc[10:14], adrs.KeyPairAddress[:])
	case address.TREE:
		copy(ADRSc[14:18], adrs.TreeHeight[:])
		copy(ADRSc[18:22], adrs.TreeIndex[:])
	case address.FORS_TREE:
		copy(ADRSc[10:14], adrs.KeyPairAddress[:])
		copy(ADRSc[14:18], adrs.TreeHeight[:])
		copy(ADRSc[18:22], adrs.TreeIndex[:])
	case address.FORS_ROOTS:
		copy(ADRSc[10:14], adrs.KeyPairAddress[:])
	}

	return ADRSc
}

// Based on RFC 2437
func mgf1sha256(seed []byte, length int) []byte {
	T := make([]byte, 0)
	counter := 0
	for len(T) < length {
		C := util.ToByte(uint64(counter), 4) //i2osp equivalent to ToByte
		hash := sha256.New()
		hash.Write(seed)
		hash.Write(C)
		hashedZC := hash.Sum(nil)
		T = append(T, hashedZC...)
		counter++
	}
	// Extract the leading l octets of T as the octet string mask.
	return T[:length]
}
