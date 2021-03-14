package WOTSplus

import (
	"math/big"
	"reflect"
	"testing"
)

// Template for test
func TestSignAndVerify(t *testing.T) {
	for i := 1; i < 100; i++ {
		PK = Wots_PKgen()
		SK = Wots_SKgen()
		signature = Wots_sign()
		if(Wots_pkFromSig != SK) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
	

}