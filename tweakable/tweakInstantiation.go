package tweakable

import "github.com/kasperdi/SPHINCSPLUS-golang/address"

const (
	Simple = "simple"
	Robust = "robust"
)

type TweakableHashFunction interface {
	Hmsg(R []byte, PKseed []byte, PKroot, M []byte) []byte
	PRF(SEED []byte, adrs *address.ADRS) []byte
	PRFmsg(SKprf []byte, OptRand []byte, M []byte) []byte
	F(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte
	H(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte
	T_l(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte
}
