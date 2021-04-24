package sphincs

import (
	"testing"
	"encoding/hex"
	"../parameters"
	"fmt"
	"../hypertree"
)

func TestSha256n256fRobust(t *testing.T) {
	//sk, pk := Spx_keygen()
	
	skseed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	pk := new(SPHINCS_PK)
	pk.PKseed = make([]byte, parameters.N)
	sk := new(SPHINCS_SK)
	sk.PKseed = make([]byte, parameters.N)
	sk.SKseed = skseed
	sk.SKprf = make([]byte, parameters.N)

	test := hypertree.Ht_PKgen(sk.SKseed, sk.PKseed)

	pk.PKroot = test
	sk.PKroot = test


	fmt.Println(hex.EncodeToString(test))
	

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