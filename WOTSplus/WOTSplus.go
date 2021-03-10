package WOTSplus
import "math"
	
// Parameters for WOTS+
const ( 
	n = 32
	w = 4
	//len1 kan findes ved: math.Ceil(8*n/math.Log2(w))
	//len2 kan findes ved: math.Floor(math.Log2(math.Ceil(8*n/math.Log2(w-1)))/math.Log2(w))+1
	//len kan findes ved: len1 + len2
)

func chain(X string, i startIndex, PKseed int, ADRS address) {
    
}

func wots_SKgen(SK.seed int, ADRS address) {

}

func wots_PKgen() {

}

func wots_sign() {

}

func wots_pkFromSig() {

}