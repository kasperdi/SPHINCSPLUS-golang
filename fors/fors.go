package fors

import (
	"math"
	"encoding/binary"
	"../util"
	"../tweakable"
	"../address"
	"../parameters"
)

type FORSSignature struct {
	forspkauth []*TreePKAUTH
}

type TreePKAUTH struct {
	privateKeyValue []byte
	AUTH []byte
}

func (s *FORSSignature) GetSK(index int) []byte {
	return s.forspkauth[index].privateKeyValue
}

func (s *FORSSignature) GetAUTH(index int) []byte {
	return s.forspkauth[index].AUTH
}


func Fors_SKgen(SKseed []byte, adrs *address.ADRS, idx int) []byte {
	hashFunc := tweakable.Sha256Tweak{}

	adrs.SetTreeHeight(0)
	adrs.SetTreeIndex(idx)
	sk := hashFunc.PRF(SKseed, adrs)
	return sk
}

func fors_treehash(SKseed []byte, startIndex int, targetNodeHeight int, PKseed []byte, adrs *address.ADRS) []byte {
	if startIndex % (1 << targetNodeHeight) != 0 {
		return nil
	}

	hashFunc := tweakable.Sha256Tweak{}
	stack := util.Stack{}

	for i := 0; i < int(math.Pow(2, float64(targetNodeHeight))); i++ {
		adrs.SetTreeHeight(0)
		adrs.SetTreeIndex(startIndex + i)
		sk := hashFunc.PRF(SKseed, adrs)
		node := hashFunc.F(tweakable.Robust, PKseed, adrs, sk)
		adrs.SetTreeHeight(1)
		adrs.SetTreeIndex(startIndex + i)
		
		for (len(stack) > 0 && (stack.Peek().NodeHeight == adrs.GetTreeHeight())) {
			adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)
			node = hashFunc.H(tweakable.Robust, PKseed, adrs, stack.Pop().Node, node)
			adrs.SetTreeHeight(adrs.GetTreeHeight() + 1)
		}
		
		stack.Push(&util.StackEntry{Node:node, NodeHeight:adrs.GetTreeHeight()})
		
	}
	
	return stack.Pop().Node
}

func Fors_PKgen(SKseed []byte, PKseed []byte, adrs *address.ADRS) []byte {
	forsPKadrs := adrs.Copy()
	root := make([]byte, parameters.K*parameters.N)
	hashFunc := tweakable.Sha256Tweak{}

	for i := 0; i < parameters.K; i++ {
		copy(root[i * parameters.N:], fors_treehash(SKseed, i*parameters.T, parameters.A, PKseed, adrs))
	}
	forsPKadrs.SetType(parameters.FORS_ROOTS)
	forsPKadrs.SetKeyPairAddress(adrs.GetKeyPairAddress())
	pk := hashFunc.T_l(tweakable.Robust, PKseed, forsPKadrs, root)
	
	return pk
}

func Fors_sign(M []byte, SKseed []byte, PKseed []byte, adrs *address.ADRS) *FORSSignature {
	hashFunc := tweakable.Sha256Tweak{}
	// compute signature elements
	SIG_FORS := new(FORSSignature)
	for i := 0; i < parameters.K; i++ {
		// get next index
		// unsigned int idx = bits i*log(t) to (i+1)*log(t) - 1 of M;
		idx := binary.BigEndian.Uint64(M)
		idx = (idx >> uint64(i+1 * parameters.LogT - 1)) & uint64(i * parameters.LogT) //CHANGE THIS
		

		// pick private key element
		adrs.SetTreeHeight(0)
		adrs.SetTreeIndex(i*parameters.T + int(idx)) // Can the int(idx) give problems due to unsigned 64 bit -> signed int conversion
		PKElement := hashFunc.PRF(SKseed, adrs)

		AUTH := make([]byte, parameters.LogT*parameters.N)
		for j := 0; j < parameters.A; j++ {
			s := int(math.Floor(float64(idx)/math.Pow(2, float64(j)))) ^ 1
			copy(AUTH[j * parameters.N:], fors_treehash(SKseed, i * parameters.T + s * int(math.Pow(2, float64(j))), j, PKseed, adrs))
		}
		SIG_FORS.forspkauth = append(SIG_FORS.forspkauth, &TreePKAUTH{PKElement, AUTH})
	}
	return SIG_FORS	
}

func Fors_pkFromSig(SIG_FORS *FORSSignature, M []byte, PKseed []byte, adrs *address.ADRS) []byte {
	hashFunc := tweakable.Sha256Tweak{}
	root := make([]byte, parameters.K*parameters.N)
	forsPKadrs := adrs.Copy()

	for i := 0; i < parameters.K; i++ {
		// get next index
		idx := binary.BigEndian.Uint64(M)
		idx = (idx >> uint64(i+1 * parameters.LogT - 1)) & uint64(i * parameters.LogT) //CHANGE THIS

		// compute leaf
		sk := SIG_FORS.GetSK(i)
		adrs.SetTreeHeight(0)
		adrs.SetTreeIndex(i * parameters.T + int(idx))
		node0 := hashFunc.F(tweakable.Robust, PKseed, adrs, sk)
		node1 := make([]byte, 0)
		
		// compute root from leaf and AUTH
		auth := SIG_FORS.GetAUTH(i)
		adrs.SetTreeIndex(i * parameters.T + int(idx))
		for j := 0; j < parameters.A; j++ {
			adrs.SetTreeHeight(j+1)
			if int(math.Floor(float64(idx) / math.Pow(2, float64(j)))) % 2 == 0 {
				adrs.SetTreeIndex(adrs.GetTreeIndex() / 2)
				node1 = hashFunc.H(tweakable.Robust, PKseed, adrs, node0, auth[j * parameters.N:(j+1)*parameters.N])
			} else {
				adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)
				node1 = hashFunc.H(tweakable.Robust, PKseed, adrs, auth[j * parameters.N:(j+1)*parameters.N], node0)
			}
			node0 = node1
		}
		copy(root[i * parameters.N:], node0)
	}

	forsPKadrs.SetType(parameters.FORS_ROOTS)
	forsPKadrs.SetKeyPairAddress(adrs.GetKeyPairAddress())
	pk := hashFunc.T_l(tweakable.Robust, PKseed, forsPKadrs, root)

	return pk
}