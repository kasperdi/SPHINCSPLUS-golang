package xmss

import (
	"math"
	"../wots"
	"../address"
	"../tweakable"
	"../parameters"
	"../util"
	"fmt"
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

	hashFunc := tweakable.Sha256Tweak{}
	stack := util.Stack{}


	for i := 0; i < int(math.Pow(2, float64(targetNodeHeight))); i++ {
		adrs.SetType(parameters.WOTS_HASH)
		adrs.SetKeyPairAddress(startIndex + i)
		node := wots.Wots_PKgen(SKseed, PKseed, adrs)
		adrs.SetType(parameters.TREE)
		adrs.SetTreeHeight(1)
		adrs.SetTreeIndex(startIndex + i)
			
		for (len(stack) > 0 && (stack.Peek().NodeHeight == targetNodeHeight)) {
			adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)
			node = hashFunc.H(tweakable.Robust, PKseed, adrs, stack.Pop().Node, node)
			adrs.SetTreeHeight(adrs.GetTreeHeight() + 1)
		}
		
		stack.Push(&util.StackEntry{Node:node, NodeHeight:adrs.GetTreeHeight()})
		
	}
	//fmt.Println(stack.Peek())
	return stack.Pop().Node
}

func Xmss_PKgen(SKseed []byte, PKseed []byte, adrs *address.ADRS) []byte {
	pk := treehash(SKseed, 0, parameters.Hmark, PKseed, adrs) 
	return pk
}

func Xmss_sign(M []byte, SKseed []byte, idx int, PKseed []byte, adrs *address.ADRS) *XMSSSignature {
	AUTH := make([]byte, parameters.Hmark * parameters.N)
	fmt.Println("SIGN")
	for i := 0; i < parameters.Hmark; i++ {
		k := int(math.Floor(float64(idx) / math.Pow(2, float64(i)))) ^ 1
		test := treehash(SKseed, k * int(math.Pow(2, float64(i))), i, PKseed, adrs)
		copy(AUTH[i * parameters.N:], test)
		fmt.Println(test)

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

	hashFunc := tweakable.Sha256Tweak{}

	// compute root from WOTS+ pk and AUTH
	adrs.SetType(parameters.TREE)
	adrs.SetTreeIndex(idx)
	fmt.Println("PKFROMSIG")
	for k := 0; k < parameters.Hmark; k++ {
		adrs.SetTreeHeight(k+1)
		if int(math.Floor(float64(idx) / math.Pow(2, float64(k)))) % 2 == 0 {
			adrs.SetTreeIndex(adrs.GetTreeIndex() / 2)
			node1 = hashFunc.H(tweakable.Robust, PKseed, adrs, node0, AUTH[k * parameters.N:(k+1)*parameters.N])
		} else {
			adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)
			node1 = hashFunc.H(tweakable.Robust, PKseed, adrs, AUTH[k * parameters.N:(k+1)*parameters.N], node0)
		}
		fmt.Println(node1)
		node0 = node1
	}
	return node0
}

