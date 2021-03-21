package parameters


const ( 
	// Parameters for WOTS+
	N = 32
	W = 4
	// len1 kan findes ved: math.Ceil(8*n/math.Log2(w))
	// len2 kan findes ved: math.Floor(math.Log2(math.Ceil(8*n/math.Log2(w-1)))/math.Log2(w))+1
	// len kan findes ved: len1 + len2

	// Parameters for XMSS

	// Parameters for HT

	// Parameters for FORS

	// Parameters for SPHINCS+
)
