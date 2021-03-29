package fors

import (
	"testing"
	"crypto/rand"
	"bytes"
	"../address"
	"../parameters"
)

// Tests that signed messages can be verified with the correct signature
func TestSignAndVerify(t *testing.T) {
	for i := 1; i < 10; i++ {
		message := make([]byte, 32)
		rand.Read(message)
		SKseed := make([]byte, 32)
		rand.Read(SKseed)
		PKseed := make([]byte, 32)
		rand.Read(SKseed)
		var adrs address.ADRS
		adrs.SetType(parameters.FORS_TREE)

		PK := Fors_PKgen(SKseed, PKseed, &adrs)

		signature := Fors_sign(message, SKseed, PKseed, &adrs)

		pkFromSig := Fors_pkFromSig(signature, message, PKseed, &adrs) 
		if(!bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
}

func TestSignVerifyWrongKey(t *testing.T) {
	for i := 1; i < 10; i++ {
		message := make([]byte, 32)
		rand.Read(message)
		wrongMessage := make([]byte, 32)
		rand.Read(wrongMessage)
		SKseed := make([]byte, 32)
		rand.Read(SKseed)
		PKseed := make([]byte, 32)
		rand.Read(SKseed)
		var adrs address.ADRS
		adrs.SetType(parameters.FORS_TREE)

		PK := Fors_PKgen(SKseed, PKseed, &adrs)

		signature := Fors_sign(message, SKseed, PKseed, &adrs)

		pkFromSig := Fors_pkFromSig(signature, wrongMessage, PKseed, &adrs) 
		if(bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
	

}