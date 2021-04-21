package sphincs

import (
	"testing"
	"encoding/hex"
	"fmt"
	"../parameters"
)

func TestSha256n256fRobust(t *testing.T) {
	//pk := new(SPHINCS_PK)
	sk := new(SPHINCS_SK)

	text := "Galinsoga subdiscoidea is a rare"
	bytesToSign := []byte(text)

	signature := Spx_sign(bytesToSign, *sk)


	fmt.Println(hex.EncodeToString(signature.R))
	for i := 0; i < parameters.K; i++ {
		fmt.Println(hex.EncodeToString(signature.SIG_FORS.GetSK(i)))
		fmt.Println(hex.EncodeToString(signature.SIG_FORS.GetAUTH(i)))
	}

	for _, xmssSig := range signature.SIG_HT.XMSSSignatures {
		fmt.Println(hex.EncodeToString(xmssSig.GetWOTSSig()))
		fmt.Println(hex.EncodeToString(xmssSig.GetXMSSAUTH()))
	}


}