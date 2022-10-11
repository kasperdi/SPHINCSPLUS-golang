package sphincs

import (
	"errors"

	"github.com/kasperdi/SPHINCSPLUS-golang/fors"
	"github.com/kasperdi/SPHINCSPLUS-golang/hypertree"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/xmss"
)

// TODO: Add error handling
func (s *SPHINCS_SIG) SerializeSignature() ([]byte, error) {
	var sig_as_bytes []byte
	sig_as_bytes = s.R
	for i := range s.SIG_FORS.Forspkauth {
		sig_as_bytes = append(sig_as_bytes, s.SIG_FORS.GetSK(i)...)
		sig_as_bytes = append(sig_as_bytes, s.SIG_FORS.GetAUTH(i)...)
	}
	for _, xmssSig := range s.SIG_HT.XMSSSignatures {
		sig_as_bytes = append(sig_as_bytes, xmssSig.GetWOTSSig()...)
		sig_as_bytes = append(sig_as_bytes, xmssSig.GetXMSSAUTH()...)
	}
	return sig_as_bytes, nil
}

func DeserializeSignature(params *parameters.Parameters, signature []byte) (*SPHINCS_SIG, error) {
	if len(signature) != (1+params.K*(params.A+1)+params.H+params.D*params.Len)*params.N {
		return nil, errors.New("Could not deserialize: Signature is of incorrect length")
	}

	SIG := new(SPHINCS_SIG)
	SIG.R = signature[:params.N]
	bytes_processed := params.N

	// Fetch bytes for fors signature and create FORSSignature struct from these
	fors_signature := new(fors.FORSSignature)
	for i := 0; i < params.K; i++ {
		// Each iteration of loop fetches one Tree PK authentication path
		pkauth := new(fors.TreePKAUTH)

		pkauth_bytes := signature[bytes_processed : bytes_processed+(params.N+params.LogT*params.N)]

		pkauth.PrivateKeyValue = pkauth_bytes[:params.N]
		pkauth.AUTH = pkauth_bytes[params.N:]

		fors_signature.Forspkauth = append(fors_signature.Forspkauth, pkauth)
		bytes_processed += params.N + params.LogT*params.N
	}

	// Fetch bytes for hypertree signature and create HTSignature struct from these
	hypertree_signature := new(hypertree.HTSignature)
	for i := 0; i < params.D; i++ {
		// Each iteration of loop fetches one XMSS signature
		xmss_sig := new(xmss.XMSSSignature)

		xmss_sig_bytes := signature[bytes_processed : bytes_processed+((params.H/params.D+params.Len)*params.N)]
		xmss_sig.WotsSignature = xmss_sig_bytes[:params.Len*params.N]
		xmss_sig.AUTH = xmss_sig_bytes[params.Len*params.N:]

		hypertree_signature.XMSSSignatures = append(hypertree_signature.XMSSSignatures, xmss_sig)
		bytes_processed += (params.H/params.D + params.Len) * params.N
	}

	SIG.SIG_FORS = fors_signature
	SIG.SIG_HT = hypertree_signature
	return SIG, nil
}

// TODO: Add error handling
func (pk *SPHINCS_PK) SerializePK() ([]byte, error) {
	var pk_as_bytes []byte
	pk_as_bytes = append(pk_as_bytes, pk.PKseed...)
	pk_as_bytes = append(pk_as_bytes, pk.PKroot...)

	return pk_as_bytes, nil
}

func DeserializePK(params *parameters.Parameters, pk []byte) (*SPHINCS_PK, error) {
	if len(pk) != 2*params.N {
		return nil, errors.New("Could not deserialize: Public key is of incorrect length")
	}

	serialized_pk := new(SPHINCS_PK)
	serialized_pk.PKseed = pk[:params.N]
	serialized_pk.PKroot = pk[params.N:]

	return serialized_pk, nil
}

// TODO: Add error handling
func (sk *SPHINCS_SK) SerializeSK() ([]byte, error) {
	var sk_as_bytes []byte
	sk_as_bytes = append(sk_as_bytes, sk.SKseed...)
	sk_as_bytes = append(sk_as_bytes, sk.SKprf...)
	sk_as_bytes = append(sk_as_bytes, sk.PKseed...)
	sk_as_bytes = append(sk_as_bytes, sk.PKroot...)

	return sk_as_bytes, nil
}

func DeserializeSK(params *parameters.Parameters, sk []byte) (*SPHINCS_SK, error) {
	if len(sk) != 4*params.N {
		return nil, errors.New("Could not deserialize: Secret key is of incorrect length")
	}

	serialized_sk := new(SPHINCS_SK)
	serialized_sk.SKseed = sk[:params.N]
	serialized_sk.SKprf = sk[params.N : 2*params.N]
	serialized_sk.PKseed = sk[2*params.N : 3*params.N]
	serialized_sk.PKroot = sk[3*params.N:]

	return serialized_sk, nil
}
