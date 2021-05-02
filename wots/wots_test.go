package wots

import (
	"testing"
	"crypto/rand"
	"encoding/hex"
	"bytes"
	"io/ioutil"
	"../address"
	"../parameters"
	"fmt"
)

// Tests that signed messages can be verified with the correct signature
func TestSignAndVerify(t *testing.T) {
	params := parameters.MakeSphincsPlusSHA256256fRobust(false)
	for i := 0; i < 10; i++ {
		message := make([]byte, params.N)
		rand.Read(message)
		SKseed := make([]byte, params.N)
		rand.Read(SKseed)
		PKseed := make([]byte, params.N)
		rand.Read(SKseed)
		var adrs address.ADRS  // Are 3 needed?

		PK := Wots_PKgen(params, SKseed, PKseed, &adrs)

		signature := Wots_sign(params ,message, SKseed, PKseed, &adrs)

		pkFromSig := Wots_pkFromSig(params, signature, message, PKseed, &adrs)

		if(!bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
	
}

// Ensures that a wrong key cannot be used to verify a message
func TestSignVerifyWrongKey(t *testing.T) {
	params := parameters.MakeSphincsPlusSHA256256fRobust(false)
	for i := 0; i < 10; i++ {
		message := make([]byte, params.N)
		rand.Read(message)
		wrongMessage := make([]byte, params.N)
		rand.Read(wrongMessage)
		SKseed := make([]byte, params.N)
		rand.Read(SKseed)
		PKseed := make([]byte, params.N)
		rand.Read(SKseed)
		var adrs address.ADRS  // Are 3 needed?
		var adrs2 address.ADRS
		var adrs3 address.ADRS  

		PK := Wots_PKgen(params, SKseed, PKseed, &adrs)

		signature := Wots_sign(params, message, SKseed, PKseed, &adrs2)

		pkFromSig := Wots_pkFromSig(params, signature, wrongMessage, PKseed, &adrs3)
		if(bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message succeeded, but was expected to fail!")
		}
	}
}

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
		//{Param: parameters.MakeSphincsPlusSHA256192fSimple(false), SphincsVariant: "SHA256192f-Simple"},
		//{Param: parameters.MakeSphincsPlusSHA256192sSimple(false), SphincsVariant: "SHA256192s-Simple"},

		{Param: parameters.MakeSphincsPlusSHA256128fRobust(false), SphincsVariant: "SHA256128f-Robust"},
		{Param: parameters.MakeSphincsPlusSHA256128sRobust(false), SphincsVariant: "SHA256128s-Robust"},
		//{Param: parameters.MakeSphincsPlusSHA256128fSimple(false), SphincsVariant: "SHA256128f-Simple"},
		//{Param: parameters.MakeSphincsPlusSHA256128sSimple(false), SphincsVariant: "SHA256128s-Simple"},

		{Param: parameters.MakeSphincsPlusSHAKE256256fRobust(false), SphincsVariant: "SHAKE256256f-Robust"},
		{Param: parameters.MakeSphincsPlusSHAKE256256sRobust(false), SphincsVariant: "SHAKE256256s-Robust"},
		{Param: parameters.MakeSphincsPlusSHAKE256256fSimple(false), SphincsVariant: "SHAKE256256f-Simple"},
		{Param: parameters.MakeSphincsPlusSHAKE256256sSimple(false), SphincsVariant: "SHAKE256256s-Simple"},

		{Param: parameters.MakeSphincsPlusSHAKE256192fRobust(false), SphincsVariant: "SHAKE256192f-Robust"},
		{Param: parameters.MakeSphincsPlusSHAKE256192sRobust(false), SphincsVariant: "SHAKE256192s-Robust"},
		//{Param: parameters.MakeSphincsPlusSHAKE256192fSimple(false), SphincsVariant: "SHAKE256192f-Simple"},
		//{Param: parameters.MakeSphincsPlusSHAKE256192sSimple(false), SphincsVariant: "SHAKE256192s-Simple"},

		{Param: parameters.MakeSphincsPlusSHAKE256128fRobust(false), SphincsVariant: "SHAKE256128f-Robust"},
		{Param: parameters.MakeSphincsPlusSHAKE256128sRobust(false), SphincsVariant: "SHAKE256128s-Robust"},
		//{Param: parameters.MakeSphincsPlusSHAKE256128fSimple(false), SphincsVariant: "SHAKE256128f-Simple"},
		//{Param: parameters.MakeSphincsPlusSHAKE256128sSimple(false), SphincsVariant: "SHAKE256128s-Simple"},

	}

	for _, paramVal := range cases {
		t.Run(fmt.Sprintf("Keygen %s", paramVal.SphincsVariant), func(t *testing.T) { testSignFixed(t, paramVal.Param, paramVal.SphincsVariant) })
	}
}

func testSignFixed(t *testing.T, params *parameters.Parameters, SphincsVariant string) {
	bytes, err := ioutil.ReadFile("expected_signatures/expected-wots-" + SphincsVariant + ".txt")
	if err != nil {
		t.Errorf("Expected result file missing!")
	}
	tmp := make([]byte, params.N)
	for i := 0; i < params.N; i++ {
		tmp[i] = byte(i);
	}
	SKseed := make([]byte, params.N)
	var adrs address.ADRS

	signature := Wots_sign(params, tmp, SKseed, tmp, &adrs)
	SignatureAsString := hex.EncodeToString(signature)

	expected := string(bytes)

	if SignatureAsString != expected {
		t.Errorf("Error: Got %s", SignatureAsString)
	}
}