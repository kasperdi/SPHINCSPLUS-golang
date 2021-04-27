package tweakable

import "../address"

const (
    Simple = "simple"
    Robust = "robust"
)

type tweakableHashFunction interface {
    Hmsg(R []byte, PKseed []byte, PKroot, M []byte) []byte
    PRF(SEED []byte, adrs *address.ADRS) []byte
    PRFmsg(SKprf []byte, OptRand []byte, M []byte) []byte
    F(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte
    H(PKseed []byte, adrs *address.ADRS, tmp1 []byte, tmp2 []byte) []byte
    T_l(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte
}