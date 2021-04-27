package tweakable

import (
	"golang.org/x/crypto/sha3"
	"math"
	"../address"
	"../parameters"
	"../util"
)

type ShakeTweak struct {
    Variant string
}

// Tweakable hash function Hmsg
func (h *ShakeTweak) Hmsg(R []byte, PKseed []byte, PKroot []byte, M []byte) []byte {
	md_len := int(math.Floor((parameters.K * parameters.LogT + 7) / 8))
    idx_tree_len := int(math.Floor((parameters.H - parameters.H / parameters.D + 7) / 8))
    idx_leaf_len := int(math.Floor(parameters.H / parameters.D + 7) / 8)

    m := md_len + idx_tree_len + idx_leaf_len

	output := make([]byte, m)
	hash := sha3.NewShake256()
	hash.Write(R)
    hash.Write(PKseed)
    hash.Write(PKroot)
    hash.Write(M)
	hash.Read(output)
	return output
}

// Tweakable hash function PRF
func (h *ShakeTweak) PRF(SEED []byte, adrs *address.ADRS) []byte {
	output := make([]byte, parameters.N)
	hash := sha3.NewShake256()
	hash.Write(SEED)
    hash.Write(adrs.GetBytes())
	hash.Read(output)
	return output
}

// Tweakable hash function PRFmsg
func (h *ShakeTweak) PRFmsg(SKprf []byte, OptRand []byte, M []byte) []byte {
	output := make([]byte, parameters.N)
	hash := sha3.NewShake256()
	hash.Write(SKprf)
    hash.Write(OptRand)
	hash.Read(M)
	return output
}

// Tweakable hash function F
func (h *ShakeTweak) F(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	M1 := make([]byte, len(tmp))

    if h.Variant == Robust {
		bitmask := generateBitmask(PKseed, adrs, 8*len(tmp))
        M1 = util.XorBytes(tmp, bitmask) 
    } else if h.Variant == Simple {
        M1 = tmp
    }
	
	output := make([]byte, parameters.N)
	hash := sha3.NewShake256()
	hash.Write(PKseed)
    hash.Write(adrs.GetBytes())
	hash.Read(M1)
	return output
}

// Tweakable hash function H
func (h *ShakeTweak) H(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	return h.F(PKseed, adrs, tmp)
}

// Tweakable hash function T_l
func (h *ShakeTweak) T_l(PKseed []byte, adrs *address.ADRS , tmp []byte) []byte {
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
