package xmss

import (
	"math"
	"../wots"
	"../address"
	"../parameters"
	"../util"
)

type XmssParams parameters.Parameters

type XMSSSignature struct {
	wotsSignature []byte
	AUTH []byte
}

func (s *XMSSSignature) GetWOTSSig() []byte {
	return s.wotsSignature
}

func (s *XMSSSignature) GetXMSSAUTH() []byte {
	return s.AUTH
}

func (params *XmssParams) treehash(SKseed []byte, startIndex int, targetNodeHeight int, PKseed []byte, adrs *address.ADRS) []byte {
	if startIndex % (1 << targetNodeHeight) != 0 {
		return nil
	}

	stack := util.Stack{}

	for i := 0; i < int(math.Pow(2, float64(targetNodeHeight))); i++ {
		adrs.SetType(address.WOTS_HASH)
		adrs.SetKeyPairAddress(startIndex + i)
		wotsParams := wots.WotsParams(*params)
		node := wotsParams.Wots_PKgen(SKseed, PKseed, adrs)
		adrs.SetType(address.TREE)
		adrs.SetTreeHeight(1)
		adrs.SetTreeIndex(startIndex + i)
		
		for (len(stack) > 0 && (stack.Peek().NodeHeight == adrs.GetTreeHeight())) {
			adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)
			node = params.Tweak.H(PKseed, adrs, append(stack.Pop().Node, node...))
			adrs.SetTreeHeight(adrs.GetTreeHeight() + 1)
		}
		stack.Push(&util.StackEntry{Node:node, NodeHeight:adrs.GetTreeHeight()})
	}
	
	return stack.Pop().Node
}

func (params *XmssParams) Xmss_PKgen(SKseed []byte, PKseed []byte, adrs *address.ADRS) []byte {
	return params.treehash(SKseed, 0, params.Hprime, PKseed, adrs)
}

func (params *XmssParams) Xmss_sign(M []byte, SKseed []byte, idx int, PKseed []byte, adrs *address.ADRS) *XMSSSignature {
	AUTH := make([]byte, params.Hprime * params.N)
	for i := 0; i < params.Hprime; i++ {
		k := int(math.Floor(float64(idx) / math.Pow(2, float64(i)))) ^ 1
		copy(AUTH[i * params.N:], params.treehash(SKseed, k * int(math.Pow(2, float64(i))), i, PKseed, adrs))
	}
	
	adrs.SetType(address.WOTS_HASH)
	adrs.SetKeyPairAddress(idx)
	wotsParams := wots.WotsParams(*params)
	sig := wotsParams.Wots_sign(M, SKseed, PKseed, adrs)
	
	return &XMSSSignature{sig, AUTH}
}

func (params *XmssParams) Xmss_pkFromSig(idx int, SIG_XMSS *XMSSSignature, M []byte, PKseed []byte, adrs *address.ADRS) []byte {
	// compute WOTS+ pk from WOTS+ sig
	adrs.SetType(address.WOTS_HASH)
	adrs.SetKeyPairAddress(idx)
	sig := SIG_XMSS.GetWOTSSig()
	AUTH := SIG_XMSS.GetXMSSAUTH()
	
	wotsParams := wots.WotsParams(*params)
	node0 := wotsParams.Wots_pkFromSig(sig, M, PKseed, adrs)
	node1 := make([]byte, 0)

	// compute root from WOTS+ pk and AUTH
	adrs.SetType(address.TREE)
	adrs.SetTreeIndex(idx)
	for k := 0; k < params.Hprime; k++ {
		adrs.SetTreeHeight(k+1)
		if int(math.Floor(float64(idx) / math.Pow(2, float64(k)))) % 2 == 0 {
			adrs.SetTreeIndex(adrs.GetTreeIndex() / 2)

			bytesToHash := make([]byte, params.N + len(node0))
			copy(bytesToHash, node0)
			copy(bytesToHash[params.N:], AUTH[k * params.N:(k+1)*params.N])

			node1 = params.Tweak.H(PKseed, adrs, bytesToHash)
		} else {
			adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)

			bytesToHash := make([]byte, params.N + len(node0))
			copy(bytesToHash, AUTH[k * params.N:(k+1)*params.N])
			copy(bytesToHash[params.N:], node0)

			node1 = params.Tweak.H(PKseed, adrs, bytesToHash)
		}
		node0 = node1
	}
	return node0
}

