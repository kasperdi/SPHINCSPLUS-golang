package wots

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
)

func TestChainIndexStepsTooLow(t *testing.T) {
	params := parameters.MakeSphincsPlusSHA256256fRobust(false)
	var adrs address.ADRS
	res := chain(params, make([]byte, 32), 100, 100, make([]byte, 32), &adrs)
	if res != nil {
		t.Errorf("Expected nil as StartIndex + Steps > W-1, but got different result")
	}
}

// Runs the testSignFixed and testSignAndVerify subtests for all 24 implemented WOTS+ variants.
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
		t.Run(fmt.Sprintf("Wots_sig %s", paramVal.SphincsVariant), func(t *testing.T) { testSignFixed(t, paramVal.Param, paramVal.SphincsVariant) })
		t.Run(fmt.Sprintf("Wots_sig %s", paramVal.SphincsVariant), func(t *testing.T) { testSignAndVerify(t, paramVal.Param) })
	}
}

// Uses signatures generated using the reference C WOTS+ implementation to ensure that this implementation returns the same signature.
func testSignFixed(t *testing.T, params *parameters.Parameters, SphincsVariant string) {
	bytes, err := ioutil.ReadFile("expected_signatures/expected-wots-" + SphincsVariant + ".txt")
	if err != nil {
		t.Errorf("Expected result file missing!")
		return
	}
	message := []byte("YTwkwhkyJG3PMpDWlEvRuN0BppYASt3J")[:params.N]
	PKSeed := make([]byte, params.N)
	for i := 0; i < params.N; i++ {
		PKSeed[i] = byte(i)
	}
	SKseed := make([]byte, params.N)
	var adrs address.ADRS

	signature := Wots_sign(params, message, SKseed, PKSeed, &adrs)
	SignatureAsString := hex.EncodeToString(signature)

	expected := string(bytes)

	if SignatureAsString != expected {
		t.Errorf("Error: Got %s", SignatureAsString)
	}
}

// Simple consistency check test inspired by the tests in the reference implementation.
func testSignAndVerify(t *testing.T, params *parameters.Parameters) {
	message := make([]byte, params.N)
	rand.Read(message)
	SKseed := make([]byte, params.N)
	rand.Read(SKseed)
	PKseed := make([]byte, params.N)
	rand.Read(SKseed)
	var adrs address.ADRS

	PK := Wots_PKgen(params, SKseed, PKseed, &adrs)
	signature := Wots_sign(params, message, SKseed, PKseed, &adrs)
	pkFromSig := Wots_pkFromSig(params, signature, message, PKseed, &adrs)

	if !bytes.Equal(pkFromSig, PK) {
		t.Errorf("Verification of signed message failed, but was expected to succeed!")
	}

	signature[0] ^= 1 // Invalidate signature
	pkFromSig2 := Wots_pkFromSig(params, signature, message, PKseed, &adrs)

	if bytes.Equal(pkFromSig2, PK) {
		t.Errorf("Verification of signed message succeeded, but was expected to fail!")
	}

}
