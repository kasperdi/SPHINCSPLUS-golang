package sphincs

import (
	"crypto/rand"
	"math"
	"encoding/binary"
	"../util"
	"../parameters"
	"../address"
	"../hypertree"
	"../fors"
	"../tweakable"

)

type SPHINCS_PK struct {
	PKseed []byte
	PKroot []byte
}

type SPHINCS_SK struct {
	SKseed []byte
	SKprf []byte
	PKseed []byte
	PKroot []byte
}


type SPHINCS_SIG struct {
	R []byte
	SIG_FORS *fors.FORSSignature
	SIG_HT *hypertree.HTSignature
}

func (s *SPHINCS_SIG) GetR() []byte {
	return s.R
}

func (s *SPHINCS_SIG) GetSIG_FORS() *fors.FORSSignature {
	return s.SIG_FORS
}

func (s *SPHINCS_SIG) GetSIG_HT() *hypertree.HTSignature {
	return s.SIG_HT
}


func Spx_keygen() (*SPHINCS_SK, *SPHINCS_PK) {

	SKseed := make([]byte, parameters.N)
	rand.Read(SKseed)

	SKprf := make([]byte, parameters.N)
	rand.Read(SKprf)

	PKseed := make([]byte, parameters.N)
	rand.Read(PKseed)

	PKroot := hypertree.Ht_PKgen(SKseed, PKseed)

	sk := new(SPHINCS_SK)
	sk.SKseed = SKseed
	sk.SKprf = SKprf
	sk.PKseed = PKseed
	sk.PKroot = PKroot

	pk := new(SPHINCS_PK)
	pk.PKseed = PKseed
	pk.PKroot = PKroot

	return sk, pk
}

func Spx_sign(M []byte, SK SPHINCS_SK) *SPHINCS_SIG {
	// init
	adrs := new(address.ADRS)

	// generate randomizer
	opt := make([]byte, parameters.N)
	if (parameters.RANDOMIZE) {
		rand.Read(opt)
	}

	hashFunc := tweakable.Sha256Tweak{}
	R := hashFunc.PRFmsg(SK.SKprf, opt, M)
	SIG := new(SPHINCS_SIG)
	SIG.R = R

	// compute message digest and index
	digest := hashFunc.Hmsg(R, SK.PKseed, SK.PKroot, M)
	tmp_md_bytes := int(math.Floor((parameters.K * parameters.A + 7) / 8))
	tmp_idx_tree_bytes := int(math.Floor((parameters.H - parameters.H / parameters.D + 7) / 8))
	tmp_idx_leaf_bytes := int(math.Floor(parameters.H / parameters.D + 7) / 8)

	tmp_md := digest[:tmp_md_bytes]
	tmp_idx_tree := digest[tmp_md_bytes:tmp_idx_tree_bytes]
	tmp_idx_leaf := digest[tmp_idx_tree_bytes:tmp_idx_leaf_bytes]

	md := binary.BigEndian.Uint32(tmp_md) // Should this be changed??? If k*a < 32, then we should not take all bits
	idx_tree := int(binary.BigEndian.Uint64(tmp_idx_tree) & (math.MaxUint64 >> (64 - (parameters.H - parameters.H / parameters.D)))) // Can give problems, as treaddress needs to support 12 bytes
	idx_leaf := int(binary.BigEndian.Uint32(tmp_idx_leaf) & (math.MaxUint32 >> (32 - parameters.H / parameters.D)))

	// FORS sign
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)
	adrs.SetType(parameters.FORS_TREE)
	adrs.SetKeyPairAddress(idx_leaf)

	SIG.SIG_FORS = fors.Fors_sign(util.ToByte(md, 32), SK.SKseed, SK.PKseed, adrs)

	// get FORS public key
	PK_FORS := fors.Fors_pkFromSig(SIG.SIG_FORS, M, SK.PKseed, adrs)

	// sign FORS public key with HT
	adrs.SetType(parameters.TREE)
	SIG.SIG_HT = hypertree.Ht_sign(PK_FORS, SK.SKseed, SK.PKseed, idx_tree, idx_leaf)

	return SIG
}

func Spx_verify(M []byte, SIG SPHINCS_SIG, PK SPHINCS_PK) bool {
	// init
	adrs := new(address.ADRS)
	R := SIG.GetR()
	SIG_FORS := SIG.GetSIG_FORS()
	SIG_HT := SIG.GetSIG_HT()

	// compute message digest and index
	hashFunc := tweakable.Sha256Tweak{}
	digest := hashFunc.Hmsg(R, PK.PKseed, PK.PKroot, M)
	tmp_md_bytes := int(math.Floor((parameters.K * parameters.A + 7) / 8))
	tmp_md := digest[:tmp_md_bytes]
	tmp_idx_tree_bytes := int(math.Floor((parameters.H - parameters.H / parameters.D + 7) / 8))
	tmp_idx_tree := digest[tmp_md_bytes:tmp_idx_tree_bytes]
	tmp_idx_leaf_bytes := int(math.Floor(parameters.H / parameters.D + 7) / 8)
	tmp_idx_leaf := digest[tmp_idx_tree_bytes:tmp_idx_leaf_bytes]

	md := binary.BigEndian.Uint32(tmp_md) // Should this be changed??? If k*a < 32, then we should not take all bits
	idx_tree := int(binary.BigEndian.Uint64(tmp_idx_tree) & (math.MaxUint64 >> (64 - (parameters.H - parameters.H / parameters.D))))
	idx_leaf := int(binary.BigEndian.Uint32(tmp_idx_leaf) & (math.MaxUint32 >> (32 - parameters.H / parameters.D)))
	
	// compute FORS public key
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)
	adrs.SetType(parameters.FORS_TREE)
	adrs.SetKeyPairAddress(idx_leaf)

	PK_FORS := fors.Fors_pkFromSig(SIG_FORS, util.ToByte(md, 32), PK.PKseed, adrs)

	// verify HT signature
	adrs.SetType(parameters.TREE)
	return hypertree.Ht_verify(PK_FORS, SIG_HT, PK.PKseed, idx_tree, idx_leaf, PK.PKroot)
}