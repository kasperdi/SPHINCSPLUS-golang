package hypertree

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
)

// Runs the testSignAndVerify subtest for all 24 implemented Hypertree variants.
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
	message := make([]byte, 32)
	rand.Read(message)
	SKseed := make([]byte, 32)
	rand.Read(SKseed)
	PKseed := make([]byte, 32)
	rand.Read(SKseed)

	PK := Ht_PKgen(params, SKseed, PKseed)
	signature := Ht_sign(params, message, SKseed, PKseed, 0, 0)
	if !Ht_verify(params, message, signature, PKseed, 0, 0, PK) {
		t.Errorf("Verification of signed message failed, but was expected to succeed!")
	}

	signature.XMSSSignatures[0].AUTH[0] ^= 1 // Invalidate signature
	if Ht_verify(params, message, signature, PKseed, 0, 0, PK) {
		t.Errorf("Verification of signed message succeeded, but was expected to fail!")
	}

}
