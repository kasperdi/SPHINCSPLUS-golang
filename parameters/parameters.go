package parameters

import (
	"../tweakable"
	"math"
)

type Parameters struct {
	N int
	W int
	Hprime int 
	H int
	D int
	K int
	T int
	LogT int
	A int
	RANDOMIZE bool
	Tweak tweakable.TweakableHashFunction
	Len1 int
	Len2 int
	Len int
}

func MakeSphincsPlusSHA256256fRobust(RANDOMIZE bool) *Parameters {
	params := new(Parameters)
	params.N = 32
	params.W = 16
	params.H = 68
	params.D = 17
	params.K = 35
	params.LogT = 9
	params.Hprime = params.H/params.D
	params.T = int(math.Pow(2,float64(params.LogT)))
	params.A = params.LogT
	params.RANDOMIZE = RANDOMIZE
	params.Len1 = int(math.Ceil(8*float64(params.N)/math.Log2(float64(params.W))))
	params.Len2 = int(math.Floor(math.Log2(float64(params.Len1)*(float64(params.W-1)))/math.Log2(float64(params.W)))+1)
	params.Len = params.Len1 + params.Len2
	md_len := int(math.Floor((float64(params.K) * float64(params.LogT) + 7) / 8))
    idx_tree_len := int(math.Floor((float64(params.H - params.H / params.D + 7)) / 8))
    idx_leaf_len := int(math.Floor(float64(params.H / params.D + 7)) / 8)
	M2 := md_len + idx_tree_len + idx_leaf_len
	params.Tweak = &tweakable.Sha256Tweak{tweakable.Robust, M2, params.N}
	return params
}

func MakeSphincsPlusSHA256256sRobust(RANDOMIZE bool) *Parameters {
	params := new(Parameters)
	params.N = 32
	params.W = 16
	params.H = 64
	params.D = 8
	params.K = 22
	params.LogT = 14
	params.Hprime = params.H/params.D
	params.T = int(math.Pow(2,float64(params.LogT)))
	params.A = params.LogT
	params.RANDOMIZE = RANDOMIZE
	params.Len1 = int(math.Ceil(8*float64(params.N)/math.Log2(float64(params.W))))
	params.Len2 = int(math.Floor(math.Log2(float64(params.Len1)*(float64(params.W-1)))/math.Log2(float64(params.W)))+1)
	params.Len = params.Len1 + params.Len2
	md_len := int(math.Floor((float64(params.K) * float64(params.LogT) + 7) / 8))
    idx_tree_len := int(math.Floor((float64(params.H - params.H / params.D + 7)) / 8))
    idx_leaf_len := int(math.Floor(float64(params.H / params.D + 7)) / 8)
	M2 := md_len + idx_tree_len + idx_leaf_len
	params.Tweak = &tweakable.Sha256Tweak{tweakable.Robust, M2, params.N}
	return params
}