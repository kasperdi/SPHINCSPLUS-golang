package parameters


const ( 
	// Parameters for WOTS+
	N = 32
	W = 16
	
	// Parameters for XMSS
	Hmark = H/D

	// Parameters for HT
	H = 68
	D = 17

	// Parameters for FORS
	K = 35
	T = 512
	LogT = 9
	A = 9

	// Parameters for SPHINCS+

	// ADRS types
	WOTS_HASH = 0
	WOTS_PK = 1
	TREE = 2
	FORS_TREE = 3
	FORS_ROOTS = 4
	
)
