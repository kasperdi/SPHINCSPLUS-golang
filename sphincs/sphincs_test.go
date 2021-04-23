package sphincs

import (
	"testing"
	"encoding/hex"
	"../parameters"
	"fmt"
)

func TestSha256n256fRobust(t *testing.T) {
	//sk, pk := Spx_keygen()
	pk := new(SPHINCS_PK)
	pk.PKseed = make([]byte, parameters.N)
	pk.PKroot = make([]byte, parameters.N)
	sk := new(SPHINCS_SK)
	sk.PKseed = make([]byte, parameters.N)
	sk.PKroot = make([]byte, parameters.N)
	sk.SKseed = make([]byte, parameters.N)
	sk.SKprf = make([]byte, parameters.N)


	text := "Galinsoga subdiscoidea is a rare"
	bytesToSign := []byte(text)

	signature := Spx_sign(bytesToSign, *sk)

	if(!Spx_verify(bytesToSign, *signature, *pk)) {
		t.Errorf("Verification failed, but was expected to succeed")
	}

	fmt.Println("Signature")
	fmt.Print(hex.EncodeToString(signature.R))
	for i := 0; i < parameters.K; i++ {
		fmt.Print(hex.EncodeToString(signature.SIG_FORS.GetSK(i)))
		fmt.Print(hex.EncodeToString(signature.SIG_FORS.GetAUTH(i)))
	}

	for _, xmssSig := range signature.SIG_HT.XMSSSignatures {
		fmt.Print(hex.EncodeToString(xmssSig.GetWOTSSig()))
		fmt.Print(hex.EncodeToString(xmssSig.GetXMSSAUTH()))
	}

	fmt.Println("")


}