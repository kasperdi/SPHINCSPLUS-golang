package tweakable

import "fmt"
import "crypto/sha256"
import "math/rand"
import "./util"  

type sha256Tweak struct {
    
}

func (h *sha256Tweakable) Hmsg(R []byte, PKseed *big.Int, PKroot, M []byte) {
    fmt.Println("test")
}

func (h *sha256Tweakable) PRF(SEED *big.Int, address *ADRS) {
    SEEDBytes := SEED.Bytes()
    compressedADRS := compressADRS(address)
    concatenatedSEEDADRSc := append(SEEDBytes, compressedADRS)
    return hashMessage(concatenatedSEEDADRSc)
}

func (h *sha256Tweakable) PRFmsg(SKprf *big.Int, OptRand *big.Int, M []byte) {
    fmt.Println("test")
}

func (h *sha256Tweakable) F(v variant, PKseed *big.Int, address *ADRS, tmp []byte) {
    fmt.Println("test")
}

func (h *sha256Tweakable) H(v variant, PKseed *big.Int, address *ADRS, tmp []byte) {
    fmt.Println("test")
}

func (h *sha256Tweakable) T_l(v variant, PKseed *big.Int, address *ADRS, tmp []byte) {
    fmt.Println("test")
}

func hashMessage(message []byte) {
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
func compressADRS(address *ADRS) []byte {
    ADRSc = make([]byte, 22)
    
    // Extract least significant byte of layer address
    copy(ADRS.LayerAddress[0:1], ADRSc[0:1])
    // Extract least significant 8 bytes of tree address
    copy(ADRS.TreeAddress[0:8], ADRSc[1:9])
    // Extract least significant byte of type field
    copy(util.ToByte(ADRS.Type[0:1]), ADRSc[9:10]) //TODO: LITTLE ENDIAN OR BIG ENDIAN???

    // Copy rest of ADRS
    copy(ADRS.KeyPairAddress, ADRSc[10:14])
    // copy(ADRS.TreeHeight, ADRSc[15:19]) TODO: SKAL DE HER IKKE MED?
    // copy(ADRS.TreeIndex, ADRSc[19:23]) TODO: SKAL DE HER IKKE MED?
    copy(ADRS.ChainAddress, ADRSc[14:18])
    copy(ADRS.HashAddress, ADRSc[18:22])

    return ADRSc
}