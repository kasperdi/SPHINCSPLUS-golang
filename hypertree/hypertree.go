package hypertree

import (
	"bytes"
	"../xmss"
	"../address"
	"../parameters"
)

type HTSignature struct {
	XMSSSignatures []*xmss.XMSSSignature
}

func (s *HTSignature) GetXMSSSignature(index int) *xmss.XMSSSignature {
	return s.XMSSSignatures[index]
}


func Ht_PKgen(SKseed []byte, PKseed []byte) []byte {
	// Equivalent to ADRS = toByte(0, 32) in the pseudocode
	adrs := new(address.ADRS)
	adrs.SetLayerAddress(parameters.D-1)
	adrs.SetTreeAddress(0)
	root := xmss.Xmss_PKgen(SKseed, PKseed, adrs)
	return root
}

func Ht_sign(M []byte, SKseed []byte, PKseed []byte, idx_tree int, idx_leaf int) *HTSignature {
	// init
	adrs := new(address.ADRS)
	
	// sign
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)
	SIG_tmp := xmss.Xmss_sign(M, SKseed, idx_leaf, PKseed, adrs)
	SIG_HT := make([]*xmss.XMSSSignature, 0)
	SIG_HT = append(SIG_HT, SIG_tmp)
	root := xmss.Xmss_pkFromSig(idx_leaf, SIG_tmp, M, PKseed, adrs)
	for j := 1; j < parameters.D; j++ {
		// idx_leaf = (h / d) least significant bits of idx_tree;
		idx_leaf = idx_tree % (1 << (parameters.H/parameters.D))
		// idx_tree = (h - (j + 1) * (h / d)) most significant bits of idx_tree;
		idx_tree = idx_tree >> (parameters.H/parameters.D) // Can this be changed to idx_tree >> parameters.H/parameters.D
		adrs.SetLayerAddress(j)
		adrs.SetTreeAddress(idx_tree)
		SIG_tmp = xmss.Xmss_sign(root, SKseed, idx_leaf, PKseed, adrs)
		SIG_HT = append(SIG_HT, SIG_tmp)
		if (j < parameters.D-1) {
			root = xmss.Xmss_pkFromSig(idx_leaf, SIG_tmp, root, PKseed, adrs)
		}
	}

	return &HTSignature{SIG_HT}
}

func Ht_verify(M []byte, SIG_HT *HTSignature, PKseed []byte, idx_tree int, idx_leaf int, PK_HT []byte) bool {
	// init
	adrs := new(address.ADRS)

	// verify
	SIG_tmp := SIG_HT.GetXMSSSignature(0)
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)
	node := xmss.Xmss_pkFromSig(idx_leaf, SIG_tmp, M, PKseed, adrs)
	
	for j := 1; j < parameters.D; j++ {
		idx_leaf = ^((^0) << (parameters.H/parameters.D)) & idx_tree
		idx_tree = idx_tree >> (parameters.H/parameters.D) // Can this be changed to idx_tree >> parameters.H/parameters.D
		SIG_tmp = SIG_HT.GetXMSSSignature(j)
		adrs.SetLayerAddress(j)
		adrs.SetTreeAddress(idx_tree)
		node = xmss.Xmss_pkFromSig(idx_leaf, SIG_tmp, node, PKseed, adrs)
	}
	
	return bytes.Equal(node, PK_HT)
}

