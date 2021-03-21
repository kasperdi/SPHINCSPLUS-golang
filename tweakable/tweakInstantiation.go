package tweakable

import "math/big"
import "../address"

const (
    simple = "simple"
    robust = "robust"
)

type tweakableHashFunction interface {
    Hmsg(R []byte, PKseed *big.Int, PKroot, M []byte) []byte
    PRF(SEED *big.Int, adrs *address.ADRS) []byte
    PRFmsg(SKprf *big.Int, OptRand *big.Int, M []byte) []byte
    F(variant string, PKseed *big.Int, adrs *address.ADRS, tmp []byte) []byte
    H(variant string, PKseed *big.Int, adrs *address.ADRS, tmp1 []byte, tmp2 []byte) []byte
    T_l(variant string, PKseed *big.Int, adrs *address.ADRS, tmp []byte) []byte
}