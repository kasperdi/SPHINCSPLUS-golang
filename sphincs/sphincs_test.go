package sphincs

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/kasperdi/SPHINCSPLUS-golang/hypertree"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
)

// Runs the testSignFixed and testSignAndVerify subtests for all 24 implemented variants.
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
		t.Run(fmt.Sprintf("Spx_sig %s", paramVal.SphincsVariant), func(t *testing.T) { testSignFixed(t, paramVal.Param, paramVal.SphincsVariant) })
		t.Run(fmt.Sprintf("Spx_sig %s", paramVal.SphincsVariant), func(t *testing.T) { testSignAndVerify(t, paramVal.Param) })
	}
}

// Uses signatures generated using the reference C implementation to ensure that this implementation returns the same signature.
func testSignFixed(t *testing.T, params *parameters.Parameters, SphincsVariant string) {
	bytes, err := ioutil.ReadFile("expected_signatures/expected-spx-" + SphincsVariant + ".txt")
	if err != nil {
		t.Errorf("Expected result file missing!")
		return
	}
	pk := new(SPHINCS_PK)
	pk.PKseed = make([]byte, params.N)
	sk := new(SPHINCS_SK)
	sk.PKseed = make([]byte, params.N)
	sk.SKseed = make([]byte, params.N)
	sk.SKprf = make([]byte, params.N)
	root := hypertree.Ht_PKgen(params, sk.SKseed, sk.PKseed)
	pk.PKroot = root
	sk.PKroot = root

	message := []byte("EGfSg8kYRjvejx4QzVMOlr4PwzjjUeoim9tKEffzcsXw1ml8burlqHkA1tr4mVGp")

	signature := Spx_sign(params, message, sk)
	SignatureAsString := ""
	SignatureAsString += hex.EncodeToString(signature.R)
	for i := 0; i < params.K; i++ {
		SignatureAsString += hex.EncodeToString(signature.SIG_FORS.GetSK(i))
		SignatureAsString += hex.EncodeToString(signature.SIG_FORS.GetAUTH(i))
	}
	for _, xmssSig := range signature.SIG_HT.XMSSSignatures {
		SignatureAsString += hex.EncodeToString(xmssSig.GetWOTSSig())
		SignatureAsString += hex.EncodeToString(xmssSig.GetXMSSAUTH())
	}

	expected := string(bytes)
	if SignatureAsString != expected {
		t.Errorf("Error: Got %s", SignatureAsString)
	}
}

// Simple consistency check test inspired by the tests in the reference implementation
func testSignAndVerify(t *testing.T, params *parameters.Parameters) {
	message := make([]byte, params.N)
	rand.Read(message)

	sk, pk := Spx_keygen(params)
	signature := Spx_sign(params, message, sk)

	if !Spx_verify(params, message, signature, pk) {
		t.Errorf("Verification failed, but was expected to succeed")
	}

	signature.R[0] ^= 1
	if Spx_verify(params, message, signature, pk) {
		t.Errorf("Verification succeeded, but was expected to fail")
	}
}

func TestSignAndVerifyNondeterministic(t *testing.T) {
	params := parameters.MakeSphincsPlusSHA256256fRobust(true)

	message := make([]byte, params.N)
	rand.Read(message)

	sk, pk := Spx_keygen(params)
	signature := Spx_sign(params, message, sk)

	if !Spx_verify(params, message, signature, pk) {
		t.Errorf("Verification failed, but was expected to succeed")
	}

}

// ------- BENCHMARKING -------
func BenchmarkSphincsPlus(b *testing.B) {
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
		b.Run(fmt.Sprintf("Keygen %s", paramVal.SphincsVariant), func(b *testing.B) { benchmarkKeygen(b, paramVal.Param) })
		b.Run(fmt.Sprintf("Sign %s", paramVal.SphincsVariant), func(b *testing.B) { benchmarkSign(b, paramVal.Param) })
		b.Run(fmt.Sprintf("Verify %s", paramVal.SphincsVariant), func(b *testing.B) { benchmarkVerify(b, paramVal.Param) })
	}
}

func benchmarkKeygen(b *testing.B, params *parameters.Parameters) {
	for i := 0; i < b.N; i++ {
		Spx_keygen(params)
	}
}

func benchmarkSign(b *testing.B, params *parameters.Parameters) {
	message := make([]byte, 32)
	rand.Read(message)
	sk, _ := Spx_keygen(params)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Spx_sign(params, message, sk)
	}

}

func benchmarkVerify(b *testing.B, params *parameters.Parameters) {
	message := make([]byte, 32)
	rand.Read(message)
	sk, pk := Spx_keygen(params)
	sig := Spx_sign(params, message, sk)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Spx_verify(params, message, sig, pk)
	}
}
