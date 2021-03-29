package hypertree

import (
	"testing"
	"crypto/rand"
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

		PK := Ht_PKgen(SKseed, PKseed)

		signature := Ht_sign(message, SKseed, PKseed, 0, 0)

		if (!Ht_verify(message, signature, PKseed, 0, 0, PK)) {
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

		PK := Ht_PKgen(SKseed, PKseed)

		signature := Ht_sign(message, SKseed, PKseed, 0, 0)

		if (Ht_verify(wrongMessage, signature, PKseed, 0, 0, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
	

}