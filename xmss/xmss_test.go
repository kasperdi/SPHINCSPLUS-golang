package xmss

import (
	"testing"
	"crypto/rand"
	"bytes"
	"../address"
)

// Tests that signed messages can be verified with the correct signature
func TestSignAndVerify(t *testing.T) {
	for i := 1; i < 100; i++ {
		message := make([]byte, 32)
		rand.Read(message)
		SKseed := make([]byte, 32)
		rand.Read(SKseed)
		PKseed := make([]byte, 32)
		rand.Read(SKseed)
		var adrs address.ADRS // Are 3 needed?
		var adrs2 address.ADRS
		var adrs3 address.ADRS

		PK := Xmss_PKgen(SKseed, PKseed, &adrs)

		signature := Xmss_sign(message, SKseed, 0, PKseed, &adrs2)

		pkFromSig := Xmss_pkFromSig(0, signature, message, PKseed, &adrs3) 
		if(!bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
}

func TestSignVerifyWrongKey(t *testing.T) {
	for i := 1; i < 100; i++ {
		message := make([]byte, 32)
		rand.Read(message)
		wrongMessage := make([]byte, 32)
		rand.Read(wrongMessage)
		SKseed := make([]byte, 32)
		rand.Read(SKseed)
		PKseed := make([]byte, 32)
		rand.Read(SKseed)
		var adrs address.ADRS // Are 3 needed?
		var adrs2 address.ADRS
		var adrs3 address.ADRS

		PK := Xmss_PKgen(SKseed, PKseed, &adrs)

		signature := Xmss_sign(message, SKseed, 0, PKseed, &adrs2)

		pkFromSig := Xmss_pkFromSig(0, signature, wrongMessage, PKseed, &adrs3) 
		if(bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
	

}