package WOTSplus

import (
	"testing"
	"crypto/rand"
	"fmt"
	"bytes"
	"../address"
)

// Template for test
func TestSignAndVerify(t *testing.T) {
	for i := 1; i < 100; i++ {
		message := make([]byte, 32)
		_, err := rand.Read(message)
		if err != nil {
			fmt.Println("ERROR GENERATING MSG")
		}

		SKseed := make([]byte, 32)
		_, err2 := rand.Read(SKseed)
		if err2 != nil {
			fmt.Println("ERROR GENERATING SKSEED")
		}

		PKseed := make([]byte, 32)
		_, err3 := rand.Read(SKseed)
		if err3 != nil {
			fmt.Println("ERROR GENERATING PKSEED")
		}

		var adrs address.ADRS

		PK := Wots_PKgen(SKseed, PKseed, &adrs)

		//SK := Wots_SKgen(SKseed, &adrs)

		signature := Wots_sign(message, SKseed, PKseed, &adrs)

		pkFromSig := Wots_pkFromSig(signature, message, PKseed, &adrs)
		if(!bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
	

}