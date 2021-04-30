package sphincs

import (
	"testing"
	"encoding/hex"
	"crypto/rand"
	"../parameters"
	"../hypertree"
	/* "fmt" */
)

func TestSha256n256fRobust(t *testing.T) {
	//sk, pk := Spx_keygen()
	
	skprf, _ := hex.DecodeString("47616c696e736f676120737562646973636f6964656120697320612072617265")

	pk := new(SPHINCS_PK)
	pk.PKseed = make([]byte, parameters.N)
	sk := new(SPHINCS_SK)
	sk.PKseed = make([]byte, parameters.N)
	sk.SKseed = make([]byte, parameters.N)
	sk.SKprf = skprf

	root := hypertree.Ht_PKgen(sk.SKseed, sk.PKseed)

	pk.PKroot = root
	sk.PKroot = root

	text := "Galinsoga subdiscoidea is a rare"
	bytesToSign := []byte(text)

	signature := Spx_sign(bytesToSign, sk)

	if(!Spx_verify(bytesToSign, signature, pk)) {
		t.Errorf("Verification failed, but was expected to succeed")
	}

	/* fmt.Println("Signature")
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

	t.Errorf("Verification failed, but was expected to succeed") */
}


func TestSignAndVerify(t *testing.T) {
	for i := 0; i < 5; i++ {

		message := make([]byte, parameters.N)
		rand.Read(message)

		sk, pk := Spx_keygen()
		signature := Spx_sign(message, sk)

		if(!Spx_verify(message, signature, pk)) {
			t.Errorf("Verification failed, but was expected to succeed")
		}
	}
	
}

func BenchmarkKeygen(b *testing.B) {
	for i := 0; i < b.N; i++ {	
		Spx_keygen()
	}
}

func BenchmarkSign(b *testing.B) {
	message := make([]byte, 32)
	rand.Read(message)
	sk, _ := Spx_keygen()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {	
		Spx_sign(message, sk)
	}
	
}

func BenchmarkVerify(b *testing.B) {
	message := make([]byte, 32)
	rand.Read(message)
	sk, pk := Spx_keygen()
	sig := Spx_sign(message, sk)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {	
		Spx_verify(message, sig, pk)
	}
}

