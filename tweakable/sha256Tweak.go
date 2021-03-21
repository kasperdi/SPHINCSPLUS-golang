package tweakable

import (
    "crypto/sha256"
    "crypto/hmac"
    "encoding/binary"
    "../util"
    "../address"
    "../parameters"
)

type Sha256Tweak struct {
    
}

// Tweakable hash function Hmsg
func (h *Sha256Tweak) Hmsg(R []byte, PKseed []byte, PKroot []byte, M []byte) []byte {
    concatenatedParams := append(append(append(R, PKseed...), PKroot...), M...)
    hashedConc := hashMessage(concatenatedParams)
    bitmask := mgf1sha256(hashedConc, 32)
    return bitmask
}

// Tweakable hash function PRF
func (h *Sha256Tweak) PRF(SEED []byte, adrs *address.ADRS) []byte {
    compressedADRS := compressADRS(adrs)
    concatenatedSEEDADRSc := append(SEED, compressedADRS...)
    return hashMessage(concatenatedSEEDADRSc)
}

// Tweakable hash function PRFmsg
func (h *Sha256Tweak) PRFmsg(SKprf []byte, OptRand []byte, M []byte) []byte {
    OptMConcatenated := append(OptRand, M...)
    mac := hmac.New(sha256.New, SKprf)
    mac.Write(OptMConcatenated)
    return mac.Sum(nil)
}

// Tweakable hash function F
func (h *Sha256Tweak) F(variant string, PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
    M1 := make([]byte, len(tmp))
    compressedADRS := compressADRS(adrs)

    if variant == Robust {
        bitmask := mgf1sha256(append(PKseed, compressedADRS...), len(tmp))
        M1 = xorBytes(tmp, bitmask) 
    } else if variant == Simple {
        M1 = tmp
    }

    bytes := util.ToByte(0,64-parameters.N)
    concatenatedParams := append(append(append(PKseed, bytes...), compressedADRS...), M1...)
    
    return hashMessage(concatenatedParams)
}

// Tweakable hash function H
func (h *Sha256Tweak) H(variant string, PKseed []byte, adrs *address.ADRS, tmp1 []byte, tmp2 []byte) []byte {
    M1M2 := make([]byte, len(tmp1)+len(tmp2))
    compressedADRS := compressADRS(adrs)

    if variant == Robust {
        bitmaskM1 := mgf1sha256(append(PKseed, compressedADRS...), len(tmp1))
        M1 := make([]byte, len(tmp1))
        M1 = xorBytes(tmp1, bitmaskM1)

        bitmaskM2 := mgf1sha256(append(PKseed, compressedADRS...), len(tmp2))
        M2 := make([]byte, len(tmp2))
        M2 = xorBytes(tmp2, bitmaskM2)

        M1M2 = append(M1, M2...)
    } else if variant == Simple {
        M1M2 = append(tmp1, tmp2...)
    }

    bytes := util.ToByte(0,64-parameters.N)
    concatenatedParams := append(append(append(PKseed, bytes...), compressedADRS...), M1M2...)
    
    return hashMessage(concatenatedParams)
}

// Tweakable hash function T_l
func (h *Sha256Tweak) T_l(variant string, PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
    M := make([]byte, len(tmp))
    compressedADRS := compressADRS(adrs)

    if variant == Robust {
        bitmask := mgf1sha256(append(PKseed, compressedADRS...), len(tmp))
        M = xorBytes(tmp, bitmask) 
    } else if variant == Simple {
        M = tmp
    }

    bytes := util.ToByte(0,64-parameters.N)
    concatenatedParams := append(append(append(PKseed, bytes...), compressedADRS...), M...)
    
    return hashMessage(concatenatedParams)
}

// Hashes a message using SHA-256
func hashMessage(message []byte) []byte {
    hash := sha256.New()
    hash.Write(message)
    return hash.Sum(nil)
}

/* ADRS FORMAT
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
 */

 // Compresses ADRS into 22 bytes
func compressADRS(adrs *address.ADRS) []byte {
    ADRSc := make([]byte, 0)

    typ := binary.BigEndian.Uint32(adrs.Type[:])

    ADRSc = append(ADRSc, adrs.LayerAddress[3:4]...)
    ADRSc = append(ADRSc, adrs.TreeAddress[4:12]...)
    ADRSc = append(ADRSc, adrs.Type[3:4]...)

    switch typ {
    case 0:
        ADRSc = append(ADRSc, adrs.KeyPairAddress[:]...)
        ADRSc = append(ADRSc, adrs.ChainAddress[:]...)
        ADRSc = append(ADRSc, adrs.HashAddress[:]...)
    case 1:
        ADRSc = append(ADRSc, adrs.KeyPairAddress[:]...)
        ADRSc = append(ADRSc, util.ToByte(0, 4)...)
        ADRSc = append(ADRSc, util.ToByte(0, 4)...)
    case 2:

    case 3:

    case 4:

    }

    return ADRSc
}

// Based on https://en.wikipedia.org/wiki/Mask_generation_function
func mgf1sha256(seed []byte, length int) []byte {
    T := make([]byte, 0)
    counter := 0
    for len(T) < length {
		C := util.ToByte(uint32(counter), 4) //i2osp equivalent to ToByte
        hashedZC := hashMessage(append(seed, C...))
        T = append(T, hashedZC...)
        counter++
	}
    // Extract the leading l octets of T as the octet string mask.
    return T[:length]
}

// Returns a XOR b, where a and b has to have same length
func xorBytes(a []byte, b []byte) []byte {
    res := make([]byte, len(a))
    for i, elem := range a {
        res[i] = elem ^ b[i]
    }
    return res
}