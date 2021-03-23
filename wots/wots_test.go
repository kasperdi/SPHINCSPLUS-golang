package WOTSplus

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
		var adrs address.ADRS

		PK := Wots_PKgen(SKseed, PKseed, &adrs)

		signature := Wots_sign(message, SKseed, PKseed, &adrs)

		pkFromSig := Wots_pkFromSig(signature, message, PKseed, &adrs)
		if(!bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
	

}

// Ensures that a wrong key cannot be used to verify a message
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
		var adrs address.ADRS

		PK := Wots_PKgen(SKseed, PKseed, &adrs)

		signature := Wots_sign(message, SKseed, PKseed, &adrs)

		pkFromSig := Wots_pkFromSig(signature, wrongMessage, PKseed, &adrs)
		if(bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message succeeded, but was expected to fail!")
		}
	}
}