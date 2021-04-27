package xmss

import (
	"math"
	"../wots"
	"../address"
	"../tweakable"
	"../parameters"
	"../util"
)

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

func treehash(SKseed []byte, startIndex int, targetNodeHeight int, PKseed []byte, adrs *address.ADRS) []byte {
	if startIndex % (1 << targetNodeHeight) != 0 {
		return nil
	}

	hashFunc := tweakable.Sha256Tweak{Variant:tweakable.Robust}
	stack := util.Stack{}


	for i := 0; i < int(math.Pow(2, float64(targetNodeHeight))); i++ {
		adrs.SetType(parameters.WOTS_HASH)
		adrs.SetKeyPairAddress(startIndex + i)
		node := wots.Wots_PKgen(SKseed, PKseed, adrs)
		adrs.SetType(parameters.TREE)
		adrs.SetTreeHeight(1)
		adrs.SetTreeIndex(startIndex + i)
			
		
		for (len(stack) > 0 && (stack.Peek().NodeHeight == adrs.GetTreeHeight())) {
			adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)
			node = hashFunc.H(PKseed, adrs, append(stack.Pop().Node, node...))
			adrs.SetTreeHeight(adrs.GetTreeHeight() + 1)
		}
		
		stack.Push(&util.StackEntry{Node:node, NodeHeight:adrs.GetTreeHeight()})
		
	}
	
	return stack.Pop().Node
}

func Xmss_PKgen(SKseed []byte, PKseed []byte, adrs *address.ADRS) []byte {
	pk := treehash(SKseed, 0, parameters.Hmark, PKseed, adrs) 
	return pk
}

func Xmss_sign(M []byte, SKseed []byte, idx int, PKseed []byte, adrs *address.ADRS) *XMSSSignature {
	AUTH := make([]byte, parameters.Hmark * parameters.N)
	for i := 0; i < parameters.Hmark; i++ {
		k := int(math.Floor(float64(idx) / math.Pow(2, float64(i)))) ^ 1
		copy(AUTH[i * parameters.N:], treehash(SKseed, k * int(math.Pow(2, float64(i))), i, PKseed, adrs))

	}
	
	adrs.SetType(parameters.WOTS_HASH)
	adrs.SetKeyPairAddress(idx)
	sig := wots.Wots_sign(M, SKseed, PKseed, adrs)
	
	xmss_sig := &XMSSSignature{sig, AUTH}

	return xmss_sig
}

func Xmss_pkFromSig(idx int, SIG_XMSS *XMSSSignature, M []byte, PKseed []byte, adrs *address.ADRS) []byte {
	// compute WOTS+ pk from WOTS+ sig
	adrs.SetType(parameters.WOTS_HASH)
	adrs.SetKeyPairAddress(idx)
	sig := SIG_XMSS.GetWOTSSig()
	AUTH := SIG_XMSS.GetXMSSAUTH()
	
	node0 := wots.Wots_pkFromSig(sig, M, PKseed, adrs)
	node1 := make([]byte, 0)

	hashFunc := tweakable.Sha256Tweak{Variant:tweakable.Robust}

	// compute root from WOTS+ pk and AUTH
	adrs.SetType(parameters.TREE)
	adrs.SetTreeIndex(idx)
	for k := 0; k < parameters.Hmark; k++ {
		adrs.SetTreeHeight(k+1)
		if int(math.Floor(float64(idx) / math.Pow(2, float64(k)))) % 2 == 0 {
			adrs.SetTreeIndex(adrs.GetTreeIndex() / 2)

			bytesToHash := make([]byte, parameters.N + len(node0)) // TODO: Could be cleaned by using a byte buffer, but is it faster?
			copy(bytesToHash, node0)
			copy(bytesToHash[parameters.N:], AUTH[k * parameters.N:(k+1)*parameters.N])

			node1 = hashFunc.H(PKseed, adrs, bytesToHash)
		} else {
			adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)

			bytesToHash := make([]byte, parameters.N + len(node0)) // TODO: Could be cleaned by using a byte buffer, but is it faster?
			copy(bytesToHash, AUTH[k * parameters.N:(k+1)*parameters.N])
			copy(bytesToHash[parameters.N:], node0)

			node1 = hashFunc.H(PKseed, adrs, bytesToHash)
		}
		node0 = node1
	}
	return node0
}

