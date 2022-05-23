package xmss

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
)

// Runs XMSS subtests for all 24 variants.
func TestSphincsPlus(t *testing.T) {
	cases := []struct {
		Param          *parameters.Parameters
		SphincsVariant string
	}{
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
		t.Run(fmt.Sprintf("Fors_sig %s", paramVal.SphincsVariant), func(t *testing.T) { testSignAndVerify(t, paramVal.Param) })
	}
}

// Tests that signed messages can be verified with the correct signature, i.e. checks for consistency.
func testSignAndVerify(t *testing.T, params *parameters.Parameters) {
	for i := 0; i < 1; i++ {
		message := make([]byte, params.N)
		rand.Read(message)
		SKseed := make([]byte, params.N)
		rand.Read(SKseed)
		PKseed := make([]byte, params.N)
		rand.Read(SKseed)
		var adrs address.ADRS

		PK := Xmss_PKgen(params, SKseed, PKseed, &adrs)
		signature := Xmss_sign(params, message, SKseed, 0, PKseed, &adrs)
		pkFromSig := Xmss_pkFromSig(params, 0, signature, message, PKseed, &adrs)
		if !bytes.Equal(pkFromSig, PK) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}

		signature.AUTH[0] ^= 1 // Invalidate signature
		pkFromSig2 := Xmss_pkFromSig(params, 0, signature, message, PKseed, &adrs)
		if bytes.Equal(pkFromSig2, PK) {
			t.Errorf("Verification of signed message succeeded, but was expected to fail!")
		}
	}
}

func TestTreehashWrongArgs(t *testing.T) {
	params := parameters.MakeSphincsPlusSHA256256fRobust(false)
	var adrs address.ADRS
	res := treehash(params, make([]byte, 32), 1, 1, make([]byte, 32), &adrs)
	if res != nil {
		t.Errorf("Expected nil as StartIndex + Steps > W-1, but got different result")
	}
}

func TestSignVerifyUnevenIdx(t *testing.T) {
	params := parameters.MakeSphincsPlusSHA256256fRobust(false)
	message := make([]byte, params.N)
	SKseed := make([]byte, params.N)
	PKseed := make([]byte, params.N)
	var adrs address.ADRS

	PK := Xmss_PKgen(params, SKseed, PKseed, &adrs)
	signature := Xmss_sign(params, message, SKseed, 3, PKseed, &adrs)
	pkFromSig := Xmss_pkFromSig(params, 3, signature, message, PKseed, &adrs)
	if !bytes.Equal(pkFromSig, PK) {
		t.Errorf("Verification of signed message failed, but was expected to succeed!")
	}
}
