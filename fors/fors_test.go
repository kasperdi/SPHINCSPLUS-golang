package fors

import (
	"testing"
	"crypto/rand"
	"bytes"
	"encoding/hex"
	"../address"
	"../parameters"
)

func TestSha256n256fRobust(t *testing.T) {
	params := ForsParams(*parameters.MakeSphincsPlusSHA256256fRobust(false))
	msg := "Nola pustulata, the sharp-blotched nola, is a species of nolid moth in the family Nolidae."
	PKseed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		PKseed[i] = byte(i);
	}
	SKseed := make([]byte, 32)

	var adrs address.ADRS
	adrs.SetType(address.FORS_TREE)

	pk1 := params.Fors_PKgen(SKseed, PKseed, &adrs)
	/* fmt.Println(adrs) */

	msgAsBytes := []byte(msg)

	signature := params.Fors_sign(msgAsBytes, SKseed, PKseed, &adrs)

	pkFromSig := params.Fors_pkFromSig(signature, msgAsBytes, PKseed, &adrs)

	pkFromRefImpl := "efcc07e6dcfa255faa8b8a9f79cf55eef7632bd26fe195c61db17e9f27981c4b"

	originalPKHex := hex.EncodeToString(pk1)

	if(!bytes.Equal(pkFromSig, pk1)) {
		t.Errorf("Expected PK: %s, but got PK: %s", originalPKHex, hex.EncodeToString(pkFromSig))
	}
	
	if(pkFromRefImpl != originalPKHex) {
		t.Errorf("Expected PK: %s, but got PK: %s", pkFromRefImpl, originalPKHex)
	}

}

// Tests that signed messages can be verified with the correct signature
func TestSignAndVerify(t *testing.T) {
	params := ForsParams(*parameters.MakeSphincsPlusSHA256256fRobust(false))
	for i := 0; i < 5; i++ {
		message := make([]byte, 64)
		rand.Read(message)
		SKseed := make([]byte, params.N)
		rand.Read(SKseed)
		PKseed := make([]byte, params.N)
		rand.Read(SKseed)
		var adrs address.ADRS
		adrs.SetType(address.FORS_TREE)

		PK := params.Fors_PKgen(SKseed, PKseed, &adrs)

		signature := params.Fors_sign(message, SKseed, PKseed, &adrs)

		pkFromSig := params.Fors_pkFromSig(signature, message, PKseed, &adrs) 
		if(!bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
}

func TestSignVerifyWrongKey(t *testing.T) {
	params := ForsParams(*parameters.MakeSphincsPlusSHA256256fRobust(false))
	for i := 1; i < 5; i++ {
		message := make([]byte, 64)
		rand.Read(message)
		wrongMessage := make([]byte, 64)
		rand.Read(wrongMessage)
		SKseed := make([]byte, params.N)
		rand.Read(SKseed)
		PKseed := make([]byte, params.N)
		rand.Read(SKseed)
		var adrs address.ADRS
		adrs.SetType(address.FORS_TREE)

		PK := params.Fors_PKgen(SKseed, PKseed, &adrs)

		signature := params.Fors_sign(message, SKseed, PKseed, &adrs)

		pkFromSig := params.Fors_pkFromSig(signature, wrongMessage, PKseed, &adrs) 
		if(bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
}