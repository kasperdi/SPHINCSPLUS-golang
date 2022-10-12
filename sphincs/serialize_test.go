package sphincs

import (
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

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
	require.NoError(t, err)

	sig2, err := DeserializeSignature(params, sigBytes1)
	require.NoError(t, err)
	sigBytes2, err := sig2.SerializeSignature()
	require.NoError(t, err)
	require.Equal(t, sigBytes1, sigBytes2)

	privKeyBytes1, err := privKey1.SerializeSK()
	require.NoError(t, err)
	privKey2, err := DeserializeSK(params, privKeyBytes1)
	require.NoError(t, err)
	sig3 := Spx_sign(params, message, privKey2)

	require.True(t, Spx_verify(params, message, sig1, pubKey1))
	require.True(t, Spx_verify(params, message, sig2, pubKey1))
	require.True(t, Spx_verify(params, message, sig3, pubKey1))

	pubKeyBytes1, err := pubKey1.SerializePK()
	require.NoError(t, err)
	pubKey2, err := DeserializePK(params, pubKeyBytes1)
	require.NoError(t, err)

	require.True(t, Spx_verify(params, message, sig1, pubKey2))
	require.True(t, Spx_verify(params, message, sig2, pubKey2))
	require.True(t, Spx_verify(params, message, sig3, pubKey2))
}
