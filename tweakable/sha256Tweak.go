package tweakable

import "crypto/sha256"
import "../util"
import "math/big"
import "../address"
import "fmt"

type sha256Tweak struct {
    
}

func (h *sha256Tweak) Hmsg(R []byte, PKseed *big.Int, PKroot, M []byte) []byte {
    return nil
}

func (h *sha256Tweak) PRF(SEED *big.Int, adrs *address.ADRS) []byte {
    SEEDBytes := SEED.Bytes()
    compressedADRS := compressADRS(adrs)
    concatenatedSEEDADRSc := append(SEEDBytes, compressedADRS...)
    return hashMessage(concatenatedSEEDADRSc)
}

func (h *sha256Tweak) PRFmsg(SKprf *big.Int, OptRand *big.Int, M []byte) []byte {
    return nil
}

func (h *sha256Tweak) F(variant string, PKseed *big.Int, adrs *address.ADRS, tmp []byte) []byte {
    return nil
}

func (h *sha256Tweak) H(variant string, PKseed *big.Int, adrs *address.ADRS, tmp []byte) []byte {
    return nil
}

func (h *sha256Tweak) T_l(variant string, PKseed *big.Int, adrs *address.ADRS, tmp []byte) []byte {
    return nil
}

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
func compressADRS(adrs *address.ADRS) []byte {
    ADRSc := make([]byte, 22)
    
    // Extract least significant byte of layer address
    copy(adrs.LayerAddress[0:1], ADRSc[0:1])
    // Extract least significant 8 bytes of tree address
    copy(adrs.TreeAddress[0:8], ADRSc[1:9])
    // Extract least significant byte of type field
    copy(util.ToByte(uint32(adrs.Type), 4)[0:1], ADRSc[9:10]) //TODO: LITTLE ENDIAN OR BIG ENDIAN???

    // Copy rest of ADRS
    copy(adrs.KeyPairAddress[:], ADRSc[10:14])
    // copy(ADRS.TreeHeight, ADRSc[15:19]) TODO: SKAL DE HER IKKE MED?
    // copy(ADRS.TreeIndex, ADRSc[19:23]) TODO: SKAL DE HER IKKE MED?
    copy(adrs.ChainAddress[:], ADRSc[14:18])

    copy(util.ToByte(uint32(adrs.HashAddress), 4), ADRSc[18:22])

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