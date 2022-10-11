package sphincs

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
)

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
