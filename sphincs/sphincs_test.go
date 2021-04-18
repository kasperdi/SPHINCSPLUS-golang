package sphincs

/* import (
	"testing"
	"encoding/hex"
	"fmt"
)

func TestSha256n256fRobust(t *testing.T) {
	pk := new(SPHINCS_PK)
	sk := new(SPHINCS_SK)

	text := "Galinsoga subdiscoidea is a rare"
	bytesToSign := []byte(text)

	signature := Spx_sign(bytesToSign, *sk)


	fmt.Println(hex.EncodeToString(signature.R))
	for _, forsSig := range signature.SIG_FORS.Forspkauth {
		fmt.Println(hex.EncodeToString(forsSig.Forspkauth.privateKeyValue))
		fmt.Println(hex.EncodeToString(forsSig.Forspkauth.AUTH))
	}

	for _, htSig := range signature.SIG_HT.XMSSSignatures {
		for _, xmssSig := range htSig.XMSSSignatures {
			fmt.Println(hex.EncodeToString(xmssSig.wotsSignature))
			fmt.Println(hex.EncodeToString(xmssSig.AUTH))
		}
		
	}


} */