package sphincs

import (
	"testing"
	"encoding/hex"
	//"crypto/rand"
	"../parameters"
	"fmt"
)

func TestSha256n256fRobust(t *testing.T) {
	//sk, pk := Spx_keygen()
	
	//skseed, _ := hex.DecodeString("00020406080a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e")
	pk := new(SPHINCS_PK)
	pk.PKseed = make([]byte, parameters.N)
	sk := new(SPHINCS_SK)
	sk.PKseed = make([]byte, parameters.N)
	sk.SKseed = make([]byte, parameters.N)
	sk.SKprf = make([]byte, parameters.N)

	pk.PKroot = make([]byte, parameters.N)
	sk.PKroot = make([]byte, parameters.N)

	text := "Galinsoga subdiscoidea is a rare"
	bytesToSign := []byte(text)

	signature := Spx_sign(bytesToSign, sk)

	if(!Spx_verify(bytesToSign, signature, pk)) {
		t.Errorf("Verification failed, but was expected to succeed")
	}

	fmt.Println("Signature")
	fmt.Print(hex.EncodeToString(signature.R)) // R is now correct!!!
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

func TestSignAndVerify(t *testing.T) {
	for i := 1; i < 10; i++ {

		/* message := make([]byte, parameters.N)
		rand.Read(message) */

		text := "Galinsoga subdiscoidea is a rare"
		message := []byte(text)

		sk, pk := Spx_keygen()
		signature := Spx_sign(message, sk)

		if(!Spx_verify(message, signature, pk)) {
			t.Errorf("Verification failed, but was expected to succeed")
		}
	}
	
}