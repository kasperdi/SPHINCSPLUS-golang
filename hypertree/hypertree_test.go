package hypertree

import (
	"testing"
	"crypto/rand"
	"../parameters"
)

// Tests that signed messages can be verified with the correct signature
func TestSignAndVerify(t *testing.T) {
	params := HTParams(*parameters.MakeSphincsPlusSHA256256fRobust(false))
	for i := 0; i < 5; i++ {
		message := make([]byte, 32)
		rand.Read(message)
		SKseed := make([]byte, 32)
		rand.Read(SKseed)
		PKseed := make([]byte, 32)
		rand.Read(SKseed)

		PK := params.Ht_PKgen(SKseed, PKseed)

		signature := params.Ht_sign(message, SKseed, PKseed, 0, 0)

		if (!params.Ht_verify(message, signature, PKseed, 0, 0, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
}

func TestSignVerifyWrongKey(t *testing.T) {
	params := HTParams(*parameters.MakeSphincsPlusSHA256256fRobust(false))
	for i := 1; i < 5; i++ {
		message := make([]byte, 32)
		rand.Read(message)
		wrongMessage := make([]byte, 32)
		rand.Read(wrongMessage)
		SKseed := make([]byte, 32)
		rand.Read(SKseed)
		PKseed := make([]byte, 32)
		rand.Read(SKseed)

		PK := params.Ht_PKgen(SKseed, PKseed)

		signature := params.Ht_sign(message, SKseed, PKseed, 0, 0)

		if (params.Ht_verify(wrongMessage, signature, PKseed, 0, 0, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
	

}