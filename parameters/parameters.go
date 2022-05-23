package parameters

import (
	"math"

	"github.com/kasperdi/SPHINCSPLUS-golang/tweakable"
)

type Parameters struct {
	N         int
	W         int
	Hprime    int
	H         int
	D         int
	K         int
	T         int
	LogT      int
	A         int
	RANDOMIZE bool
	Tweak     tweakable.TweakableHashFunction
	Len1      int
	Len2      int
	Len       int
}

// SHA256-robust and N = 32
func MakeSphincsPlusSHA256256fRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(32, 16, 68, 17, 35, 9, "SHA256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHA256256sRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(32, 16, 64, 8, 22, 14, "SHA256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHA256256fSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(32, 16, 68, 17, 35, 9, "SHA256-simple", RANDOMIZE)
}
func MakeSphincsPlusSHA256256sSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(32, 16, 64, 8, 22, 14, "SHA256-simple", RANDOMIZE)
}

// SHA256-robust and N = 24
func MakeSphincsPlusSHA256192fRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 66, 22, 33, 8, "SHA256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHA256192sRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 63, 7, 17, 14, "SHA256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHA256192fSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 66, 22, 33, 8, "SHA256-simple", RANDOMIZE)
}
func MakeSphincsPlusSHA256192sSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 63, 7, 17, 14, "SHA256-simple", RANDOMIZE)
}

// SHA256-robust and N = 16
func MakeSphincsPlusSHA256128fRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 66, 22, 33, 6, "SHA256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHA256128sRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 63, 7, 14, 12, "SHA256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHA256128fSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 66, 22, 33, 6, "SHA256-simple", RANDOMIZE)
}
func MakeSphincsPlusSHA256128sSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 63, 7, 14, 12, "SHA256-simple", RANDOMIZE)
}

// SHAKE256-robust and N = 32
func MakeSphincsPlusSHAKE256256fRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(32, 16, 68, 17, 35, 9, "SHAKE256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256256sRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(32, 16, 64, 8, 22, 14, "SHAKE256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256256fSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(32, 16, 68, 17, 35, 9, "SHAKE256-simple", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256256sSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(32, 16, 64, 8, 22, 14, "SHAKE256-simple", RANDOMIZE)
}

// SHAKE256-robust and N = 24
func MakeSphincsPlusSHAKE256192fRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 66, 22, 33, 8, "SHAKE256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256192sRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 63, 7, 17, 14, "SHAKE256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256192fSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 66, 22, 33, 8, "SHAKE256-simple", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256192sSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 63, 7, 17, 14, "SHAKE256-simple", RANDOMIZE)
}

// SHAKE256-robust and N = 16
func MakeSphincsPlusSHAKE256128fRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 66, 22, 33, 6, "SHAKE256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256128sRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 63, 7, 14, 12, "SHAKE256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256128fSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 66, 22, 33, 6, "SHAKE256-simple", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256128sSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 63, 7, 14, 12, "SHAKE256-simple", RANDOMIZE)
}

func MakeSphincsPlus(n int, w int, h int, d int, k int, logt int, hashFunc string, RANDOMIZE bool) *Parameters {
	params := new(Parameters)
	params.N = n
	params.W = w
	params.H = h
	params.D = d
	params.K = k
	params.LogT = logt
	params.Hprime = params.H / params.D
	params.T = (1 << logt)
	params.A = logt
	params.RANDOMIZE = RANDOMIZE
	params.Len1 = int(math.Ceil(8 * float64(n) / math.Log2(float64(w))))
	params.Len2 = int(math.Floor(math.Log2(float64(params.Len1*(w-1)))/math.Log2(float64(w))) + 1)
	params.Len = params.Len1 + params.Len2
	md_len := int(math.Floor((float64(params.K)*float64(logt) + 7) / 8))
	idx_tree_len := int(math.Floor((float64(h - h/d + 7)) / 8))
	idx_leaf_len := int(math.Floor(float64(h/d+7)) / 8)
	m := md_len + idx_tree_len + idx_leaf_len
	switch hashFunc {
	case "SHA256-robust":
		params.Tweak = &tweakable.Sha256Tweak{tweakable.Robust, m, n}
	case "SHA256-simple":
		params.Tweak = &tweakable.Sha256Tweak{tweakable.Simple, m, n}
	case "SHAKE256-robust":
		params.Tweak = &tweakable.Shake256Tweak{tweakable.Robust, m, n}
	case "SHAKE256-simple":
		params.Tweak = &tweakable.Shake256Tweak{tweakable.Simple, m, n}
	default:
		params.Tweak = &tweakable.Sha256Tweak{tweakable.Robust, m, n}
	}
	return params
}
