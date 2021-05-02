package fors

import (
	"testing"
	"crypto/rand"
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"fmt"
	"../address"
	"../parameters"
)

func TestSphincsPlus(t *testing.T) {
	cases := []struct {
		Param *parameters.Parameters
		SphincsVariant string
	} {
		{Param: parameters.MakeSphincsPlusSHA256256fRobust(false), SphincsVariant: "SHA256256f-Robust"},
		{Param: parameters.MakeSphincsPlusSHA256256sRobust(false), SphincsVariant: "SHA256256s-Robust"},
		{Param: parameters.MakeSphincsPlusSHA256256fSimple(false), SphincsVariant: "SHA256256f-Simple"},
		{Param: parameters.MakeSphincsPlusSHA256256sSimple(false), SphincsVariant: "SHA256256s-Simple"},

		{Param: parameters.MakeSphincsPlusSHA256192fRobust(false), SphincsVariant: "SHA256192f-Robust"},
		{Param: parameters.MakeSphincsPlusSHA256192sRobust(false), SphincsVariant: "SHA256192s-Robust"},
		{Param: parameters.MakeSphincsPlusSHA256192fSimple(false), SphincsVariant: "SHA256192f-Simple"},
		{Param: parameters.MakeSphincsPlusSHA256192sSimple(false), SphincsVariant: "SHA256192s-Simple"},

		{Param: parameters.MakeSphincsPlusSHA256128fRobust(false), SphincsVariant: "SHA256128f-Robust"},
		{Param: parameters.MakeSphincsPlusSHA256128sRobust(false), SphincsVariant: "SHA256128s-Robust"},
		{Param: parameters.MakeSphincsPlusSHA256128fSimple(false), SphincsVariant: "SHA256128f-Simple"},
		{Param: parameters.MakeSphincsPlusSHA256128sSimple(false), SphincsVariant: "SHA256128s-Simple"},

		{Param: parameters.MakeSphincsPlusSHAKE256256fRobust(false), SphincsVariant: "SHAKE256256f-Robust"},
		{Param: parameters.MakeSphincsPlusSHAKE256256sRobust(false), SphincsVariant: "SHAKE256256s-Robust"},
		{Param: parameters.MakeSphincsPlusSHAKE256256fSimple(false), SphincsVariant: "SHAKE256256f-Simple"},
		{Param: parameters.MakeSphincsPlusSHAKE256256sSimple(false), SphincsVariant: "SHAKE256256s-Simple"},

		{Param: parameters.MakeSphincsPlusSHAKE256192fRobust(false), SphincsVariant: "SHAKE256192f-Robust"},
		{Param: parameters.MakeSphincsPlusSHAKE256192sRobust(false), SphincsVariant: "SHAKE256192s-Robust"},
		{Param: parameters.MakeSphincsPlusSHAKE256192fSimple(false), SphincsVariant: "SHAKE256192f-Simple"},
		{Param: parameters.MakeSphincsPlusSHAKE256192sSimple(false), SphincsVariant: "SHAKE256192s-Simple"},

		{Param: parameters.MakeSphincsPlusSHAKE256128fRobust(false), SphincsVariant: "SHAKE256128f-Robust"},
		{Param: parameters.MakeSphincsPlusSHAKE256128sRobust(false), SphincsVariant: "SHAKE256128s-Robust"},
		{Param: parameters.MakeSphincsPlusSHAKE256128fSimple(false), SphincsVariant: "SHAKE256128f-Simple"},
		{Param: parameters.MakeSphincsPlusSHAKE256128sSimple(false), SphincsVariant: "SHAKE256128s-Simple"},

	}

	for _, paramVal := range cases {
		t.Run(fmt.Sprintf("Fors_sig %s", paramVal.SphincsVariant), func(t *testing.T) { testSignFixed(t, paramVal.Param, paramVal.SphincsVariant) })
	}
}

func testSignFixed(t *testing.T, params *parameters.Parameters, SphincsVariant string) {
	bytes, err := ioutil.ReadFile("expected_signatures/expected-fors-" + SphincsVariant + ".txt")
	if err != nil {
		t.Errorf("Expected result file missing!")
		return
	}
	PKseed := make([]byte, params.N)
	for i := 0; i < params.N; i++ {
		PKseed[i] = byte(i);
	}
	SKseed := make([]byte, params.N)
	var adrs address.ADRS
	adrs.SetType(address.FORS_TREE)

	message := []byte("Q7hCGZwbUtl2uAmRGKrfZSuMXWVF29xd9vxngkvXhEya5L5vtI2DRNbLn7BPgq9O")

	signature := Fors_sign(params, message, SKseed, PKseed, &adrs)
	SignatureAsString := ""
	for i := 0; i < params.K; i++ {
		SignatureAsString += hex.EncodeToString(signature.GetSK(i))
		SignatureAsString += hex.EncodeToString(signature.GetAUTH(i))
	} 

	expected := string(bytes)

	if SignatureAsString != expected {
		t.Errorf("Error: Got %s", SignatureAsString)
	}
}

func TestSha256n256fRobustDerivePK(t *testing.T) {
	params := parameters.MakeSphincsPlusSHA256256fRobust(false)
	msg := "Nola pustulata, the sharp-blotched nola, is a species of nolid moth in the family Nolidae."
	PKseed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		PKseed[i] = byte(i);
	}
	SKseed := make([]byte, 32)
	var adrs address.ADRS
	adrs.SetType(address.FORS_TREE)

	pk1 := Fors_PKgen(params, SKseed, PKseed, &adrs)

	msgAsBytes := []byte(msg)

	signature := Fors_sign(params, msgAsBytes, SKseed, PKseed, &adrs)
	pkFromSig := Fors_pkFromSig(params, signature, msgAsBytes, PKseed, &adrs)
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
	params := parameters.MakeSphincsPlusSHA256256fRobust(false)
	for i := 0; i < 5; i++ {
		message := make([]byte, 64)
		rand.Read(message)
		SKseed := make([]byte, params.N)
		rand.Read(SKseed)
		PKseed := make([]byte, params.N)
		rand.Read(SKseed)
		var adrs address.ADRS
		adrs.SetType(address.FORS_TREE)

		PK := Fors_PKgen(params, SKseed, PKseed, &adrs)

		signature := Fors_sign(params, message, SKseed, PKseed, &adrs)

		pkFromSig := Fors_pkFromSig(params, signature, message, PKseed, &adrs) 
		if(!bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
}

func TestSignVerifyWrongKey(t *testing.T) {
	params := parameters.MakeSphincsPlusSHA256256fRobust(false)
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

		PK := Fors_PKgen(params, SKseed, PKseed, &adrs)

		signature := Fors_sign(params, message, SKseed, PKseed, &adrs)

		pkFromSig := Fors_pkFromSig(params, signature, wrongMessage, PKseed, &adrs) 
		if(bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
}