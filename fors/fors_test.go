package fors

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

// Runs the subtests below for all 24 variants.
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
		t.Run(fmt.Sprintf("Fors_sig %s", paramVal.SphincsVariant), func(t *testing.T) { testSignFixed(t, paramVal.Param, paramVal.SphincsVariant) })
		t.Run(fmt.Sprintf("Fors_sig %s", paramVal.SphincsVariant), func(t *testing.T) { testSignAndVerify(t, paramVal.Param) })
	}
}

// Uses signatures generated using the reference C FORS implementation to ensure that this implementation returns the same signature.
func testSignFixed(t *testing.T, params *parameters.Parameters, SphincsVariant string) {
	bytes, err := ioutil.ReadFile("expected_signatures/expected-fors-" + SphincsVariant + ".txt")
	if err != nil {
		t.Errorf("Expected result file missing!")
		return
	}
	PKseed := make([]byte, params.N)
	for i := 0; i < params.N; i++ {
		PKseed[i] = byte(i)
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

// Tests that signed messages can be verified with the correct signature, i.e. checks for consistency.
func testSignAndVerify(t *testing.T, params *parameters.Parameters) {
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
	if !bytes.Equal(pkFromSig, PK) {
		t.Errorf("Verification of signed message failed, but was expected to succeed!")
	}

	signature.Forspkauth[0].AUTH[0] ^= 1 // Invalidate signature
	pkFromSig2 := Fors_pkFromSig(params, signature, message, PKseed, &adrs)
	if bytes.Equal(pkFromSig2, PK) {
		t.Errorf("Verification of signed message succeeded, but was expected to fail!")
	}
}

func TestSha256n256fRobustDerivePK(t *testing.T) {
	params := parameters.MakeSphincsPlusSHA256256fRobust(false)
	msg := "Nola pustulata, the sharp-blotched nola, is a species of nolid moth in the family Nolidae."
	PKseed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		PKseed[i] = byte(i)
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

	if !bytes.Equal(pkFromSig, pk1) {
		t.Errorf("Expected PK: %s, but got PK: %s", originalPKHex, hex.EncodeToString(pkFromSig))
	}

	if pkFromRefImpl != originalPKHex {
		t.Errorf("Expected PK: %s, but got PK: %s", pkFromRefImpl, originalPKHex)
	}
}

func TestForsTreehashWrongArgs(t *testing.T) {
	params := parameters.MakeSphincsPlusSHA256256fRobust(false)
	var adrs address.ADRS
	res := Fors_treehash(params, make([]byte, 32), 1, 1, make([]byte, 32), &adrs)
	if res != nil {
		t.Errorf("Expected nil as StartIndex + Steps > W-1, but got different result")
	}
}
