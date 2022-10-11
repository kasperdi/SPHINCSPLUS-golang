package xmss

import (
	"math"

	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/util"
	"github.com/kasperdi/SPHINCSPLUS-golang/wots"
)

type XMSSSignature struct {
	WotsSignature []byte
	AUTH          []byte
}

func (s *XMSSSignature) GetWOTSSig() []byte {
	return s.WotsSignature
}

func (s *XMSSSignature) GetXMSSAUTH() []byte {
	return s.AUTH
}

func treehash(params *parameters.Parameters, SKseed []byte, startIndex int, targetNodeHeight int, PKseed []byte, adrs *address.ADRS) []byte {
	if startIndex%(1<<targetNodeHeight) != 0 {
		return nil
	}

	stack := util.Stack{}

	for i := 0; i < int(math.Pow(2, float64(targetNodeHeight))); i++ {
		adrs.SetType(address.WOTS_HASH)
		adrs.SetKeyPairAddress(startIndex + i)
		node := wots.Wots_PKgen(params, SKseed, PKseed, adrs)
		adrs.SetType(address.TREE)
		adrs.SetTreeHeight(1)
		adrs.SetTreeIndex(startIndex + i)

		for len(stack) > 0 && (stack.Peek().NodeHeight == adrs.GetTreeHeight()) {
			adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)
			node = params.Tweak.H(PKseed, adrs, append(stack.Pop().Node, node...))
			adrs.SetTreeHeight(adrs.GetTreeHeight() + 1)
		}
		stack.Push(&util.StackEntry{Node: node, NodeHeight: adrs.GetTreeHeight()})
	}

	return stack.Pop().Node
}

func Xmss_PKgen(params *parameters.Parameters, SKseed []byte, PKseed []byte, adrs *address.ADRS) []byte {
	return treehash(params, SKseed, 0, params.Hprime, PKseed, adrs)
}

func Xmss_sign(params *parameters.Parameters, M []byte, SKseed []byte, idx int, PKseed []byte, adrs *address.ADRS) *XMSSSignature {
	AUTH := make([]byte, params.Hprime*params.N)
	for i := 0; i < params.Hprime; i++ {
		k := int(math.Floor(float64(idx)/math.Pow(2, float64(i)))) ^ 1
		copy(AUTH[i*params.N:], treehash(params, SKseed, k*int(math.Pow(2, float64(i))), i, PKseed, adrs))
	}

	adrs.SetType(address.WOTS_HASH)
	adrs.SetKeyPairAddress(idx)
	sig := wots.Wots_sign(params, M, SKseed, PKseed, adrs)

	return &XMSSSignature{sig, AUTH}
}

func Xmss_pkFromSig(params *parameters.Parameters, idx int, SIG_XMSS *XMSSSignature, M []byte, PKseed []byte, adrs *address.ADRS) []byte {
	// compute WOTS+ pk from WOTS+ sig
	adrs.SetType(address.WOTS_HASH)
	adrs.SetKeyPairAddress(idx)
	sig := SIG_XMSS.GetWOTSSig()
	AUTH := SIG_XMSS.GetXMSSAUTH()

	node0 := wots.Wots_pkFromSig(params, sig, M, PKseed, adrs)
	var node1 []byte

	// compute root from WOTS+ pk and AUTH
	adrs.SetType(address.TREE)
	adrs.SetTreeIndex(idx)
	for k := 0; k < params.Hprime; k++ {
		adrs.SetTreeHeight(k + 1)
		if int(math.Floor(float64(idx)/math.Pow(2, float64(k))))%2 == 0 {
			adrs.SetTreeIndex(adrs.GetTreeIndex() / 2)

			bytesToHash := make([]byte, params.N+len(node0))
			copy(bytesToHash, node0)
			copy(bytesToHash[params.N:], AUTH[k*params.N:(k+1)*params.N])

			node1 = params.Tweak.H(PKseed, adrs, bytesToHash)
		} else {
			adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)

			bytesToHash := make([]byte, params.N+len(node0))
			copy(bytesToHash, AUTH[k*params.N:(k+1)*params.N])
			copy(bytesToHash[params.N:], node0)

			node1 = params.Tweak.H(PKseed, adrs, bytesToHash)
		}
		node0 = node1
	}
	return node0
}
