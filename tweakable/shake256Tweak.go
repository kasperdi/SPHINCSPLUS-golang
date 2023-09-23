package tweakable

import (
	"crypto/subtle"

	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"golang.org/x/crypto/sha3"
)

type Shake256Tweak struct {
	Variant             string
	MessageDigestLength int
	N                   int
}

// Keyed hash function Hmsg
func (h *Shake256Tweak) Hmsg(R []byte, PKseed []byte, PKroot []byte, M []byte) []byte {
	output := make([]byte, h.MessageDigestLength)
	hash := sha3.NewShake256()
	hash.Write(R)
	hash.Write(PKseed)
	hash.Write(PKroot)
	hash.Write(M)
	hash.Read(output)
	return output
}

// Pseudorandom function PRF
func (h *Shake256Tweak) PRF(SEED []byte, adrs *address.ADRS) []byte {
	output := make([]byte, h.N)
	hash := sha3.NewShake256()
	hash.Write(SEED)
	hash.Write(adrs.GetBytes())
	hash.Read(output)
	return output
}

// Pseudorandom function PRFmsg
func (h *Shake256Tweak) PRFmsg(SKprf []byte, OptRand []byte, M []byte) []byte {
	output := make([]byte, h.N)
	hash := sha3.NewShake256()
	hash.Write(SKprf)
	hash.Write(OptRand)
	hash.Write(M)
	hash.Read(output)
	return output
}

// Tweakable hash function F
func (h *Shake256Tweak) F(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	var M1 []byte

	if h.Variant == Robust {
		bitmask := generateBitmask(PKseed, adrs, 8*len(tmp))
		M1 = make([]byte, len(tmp))
		_ = subtle.XORBytes(M1, tmp, bitmask)
	} else if h.Variant == Simple {
		M1 = tmp
	}

	output := make([]byte, h.N)
	hash := sha3.NewShake256()
	hash.Write(PKseed)
	hash.Write(adrs.GetBytes())
	hash.Write(M1)
	hash.Read(output)
	return output
}

// Tweakable hash function H
func (h *Shake256Tweak) H(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	return h.F(PKseed, adrs, tmp)
}

// Tweakable hash function T_l
func (h *Shake256Tweak) T_l(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	return h.F(PKseed, adrs, tmp)
}

func generateBitmask(PKseed []byte, adrs *address.ADRS, messageLength int) []byte {
	output := make([]byte, messageLength)
	hash := sha3.NewShake256()
	hash.Write(PKseed)
	hash.Write(adrs.GetBytes())
	hash.Read(output)
	return output
}
