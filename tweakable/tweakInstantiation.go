package tweakable

const (
    simple = "simple"
    robust = "robust"
)

type tweakableHashFunction interface {
    Hmsg(R []byte, PKseed *big.Int, PKroot, M []byte)
    PRF(SEED *big.Int, address *ADRS)
    PRFmsg(SKprf *big.Int, OptRand *big.Int, M []byte)
    F(variant string, PKseed *big.Int, address *ADRS, tmp []byte)
    H(variant string, PKseed *big.Int, address *ADRS, tmp []byte)
    T_l(variant string, PKseed *big.Int, address *ADRS, tmp []byte)
}