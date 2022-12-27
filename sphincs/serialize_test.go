package sphincs

import (
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
)

func TestSerializeDeserialize(t *testing.T) {
	params := parameters.MakeSphincsPlusSHA256256fRobust(true)
	message := make([]byte, params.N)
	rand.Read(message)

	sk, pk := Spx_keygen(params)
	signature := Spx_sign(params, message, sk)

	// Check serialization of signature
	serialized_sig, _ := signature.SerializeSignature()
	deserialized_sig, _ := DeserializeSignature(params, serialized_sig)
	if !reflect.DeepEqual(signature, deserialized_sig) {
		t.Errorf("Serialization of signature failed")
	}

	// Check serialization of PK
	serialized_pk, _ := pk.SerializePK()
	deserialized_pk, _ := DeserializePK(params, serialized_pk)
	if !reflect.DeepEqual(pk, deserialized_pk) {
		t.Errorf("Serialization of public key failed")
	}

	// Check serialization of SK
	serialized_sk, _ := sk.SerializeSK()
	deserialized_sk, _ := DeserializeSK(params, serialized_sk)
	if !reflect.DeepEqual(sk, deserialized_sk) {
		t.Errorf("Serialization of secret key failed")
	}
}

func TestSphincsPlusSerialization(t *testing.T) {
	params := parameters.MakeSphincsPlusSHA256256fRobust(false)
	privKey1, pubKey1 := Spx_keygen(params)

	message := []byte("hello, i am a message")

	sig1 := Spx_sign(params, message, privKey1)
	sigBytes1, err := sig1.SerializeSignature()
	noError(t, err)

	sig2, err := DeserializeSignature(params, sigBytes1)
	noError(t, err)
	sigBytes2, err := sig2.SerializeSignature()
	noError(t, err)
	if !reflect.DeepEqual(sigBytes1, sigBytes2) {
		t.Errorf("Signatures do not match!")
	}

	privKeyBytes1, err := privKey1.SerializeSK()
	noError(t, err)
	privKey2, err := DeserializeSK(params, privKeyBytes1)
	noError(t, err)
	sig3 := Spx_sign(params, message, privKey2)

	verificationShouldPass(t, Spx_verify(params, message, sig1, pubKey1))
	verificationShouldPass(t, Spx_verify(params, message, sig2, pubKey1))
	verificationShouldPass(t, Spx_verify(params, message, sig3, pubKey1))

	pubKeyBytes1, err := pubKey1.SerializePK()
	noError(t, err)
	pubKey2, err := DeserializePK(params, pubKeyBytes1)
	noError(t, err)

	verificationShouldPass(t, Spx_verify(params, message, sig1, pubKey2))
	verificationShouldPass(t, Spx_verify(params, message, sig2, pubKey2))
	verificationShouldPass(t, Spx_verify(params, message, sig3, pubKey2))
}

func noError(t *testing.T, err error) {
	if err != nil {
		t.Errorf(err.Error())
	}
}

func verificationShouldPass(t *testing.T, pass bool) {
	if !pass {
		t.Errorf("Verification of signature failed")
	}
}
