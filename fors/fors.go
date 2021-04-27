package fors

import (
	"math"
	"../util"
	"../tweakable"
	"../address"
	"../parameters"
	/* "encoding/hex" */
)

type FORSSignature struct {
	Forspkauth []*TreePKAUTH
}

type TreePKAUTH struct {
	privateKeyValue []byte
	AUTH []byte
}

func (s *FORSSignature) GetSK(index int) []byte {
	return s.Forspkauth[index].privateKeyValue
}

func (s *FORSSignature) GetAUTH(index int) []byte {
	return s.Forspkauth[index].AUTH
}


func Fors_SKgen(SKseed []byte, adrs *address.ADRS, idx int) []byte {
	hashFunc := tweakable.Sha256Tweak{Variant:tweakable.Robust}

	adrs.SetTreeHeight(0)
	adrs.SetTreeIndex(idx)
	sk := hashFunc.PRF(SKseed, adrs)
	return sk
}

func Fors_treehash(SKseed []byte, startIndex int, targetNodeHeight int, PKseed []byte, adrs *address.ADRS) []byte {
	if startIndex % (1 << targetNodeHeight) != 0 {
		return nil
	}

	hashFunc := tweakable.Sha256Tweak{Variant:tweakable.Robust}
	stack := util.Stack{}
	
	for i := 0; i < int(math.Pow(2, float64(targetNodeHeight))); i++ {
		adrs.SetTreeHeight(0)
		adrs.SetTreeIndex(startIndex + i)
		sk := hashFunc.PRF(SKseed, adrs)
		node := hashFunc.F(PKseed, adrs, sk)
		
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

func Fors_PKgen(SKseed []byte, PKseed []byte, adrs *address.ADRS) []byte {
	forsPKadrs := adrs.Copy()
	root := make([]byte, parameters.K*parameters.N)
	hashFunc := tweakable.Sha256Tweak{Variant:tweakable.Robust}

	for i := 0; i < parameters.K; i++ {
		copy(root[i * parameters.N:], Fors_treehash(SKseed, i*parameters.T, parameters.A, PKseed, adrs))
	}
	forsPKadrs.SetType(address.FORS_ROOTS)
	forsPKadrs.SetKeyPairAddress(adrs.GetKeyPairAddress())
	pk := hashFunc.T_l(PKseed, forsPKadrs, root)
	
	return pk
}

// Taken from reference implementation and converted into Go code
func message_to_indices(M []byte) []int {
    offset := 0
	indices := make([]int, parameters.K)

    for i := 0; i < parameters.K; i++ {
        indices[i] = 0
        for j := 0; j < parameters.A; j++ {
            indices[i] ^= ((int(M[offset >> 3]) >> (offset & 0x7)) & 0x1) << j
            offset++
        }
    }
	return indices
}


func Fors_sign(M []byte, SKseed []byte, PKseed []byte, adrs *address.ADRS) *FORSSignature {
	hashFunc := tweakable.Sha256Tweak{Variant:tweakable.Robust}
	// compute signature elements
	SIG_FORS := new(FORSSignature)

	for i := 0; i < parameters.K; i++ {
		// get next index
		// unsigned int idx = bits i*log(t) to (i+1)*log(t) - 1 of M;
		indices := message_to_indices(M)
		
		// pick private key element
		adrs.SetTreeHeight(0)
		adrs.SetTreeIndex(i*parameters.T + indices[i]) // Can the int(idx) give problems due to unsigned 64 bit -> signed int conversion
		PKElement := hashFunc.PRF(SKseed, adrs)

		AUTH := make([]byte, parameters.A*parameters.N)
		for j := 0; j < parameters.A; j++ {
			s := int(math.Floor(float64(indices[i])/math.Pow(2, float64(j)))) ^ 1
			test := Fors_treehash(SKseed, i * parameters.T + s * int(math.Pow(2, float64(j))), j, PKseed, adrs)

			copy(AUTH[j * parameters.N:], test)
		}
		
		SIG_FORS.Forspkauth = append(SIG_FORS.Forspkauth, &TreePKAUTH{PKElement, AUTH})
	}
	return SIG_FORS
}

func Fors_pkFromSig(SIG_FORS *FORSSignature, M []byte, PKseed []byte, adrs *address.ADRS) []byte {
	hashFunc := tweakable.Sha256Tweak{Variant:tweakable.Robust}
	root := make([]byte, parameters.K*parameters.N)
	for i := 0; i < parameters.K; i++ {
		// get next index
		indices := message_to_indices(M)

		// compute leaf
		sk := SIG_FORS.GetSK(i)
		adrs.SetTreeHeight(0)
		adrs.SetTreeIndex(i * parameters.T + indices[i])
	
		node0 := hashFunc.F(PKseed, adrs, sk)
		node1 := make([]byte, 0)
		
		// compute root from leaf and AUTH
		auth := SIG_FORS.GetAUTH(i)
		
		adrs.SetTreeIndex(i * parameters.T + indices[i])
		for j := 0; j < parameters.A; j++ {
			adrs.SetTreeHeight(j+1)

			if int(math.Floor(float64(indices[i]) / math.Pow(2, float64(j)))) % 2 == 0 {
				adrs.SetTreeIndex(adrs.GetTreeIndex() / 2)

				bytesToHash := make([]byte, parameters.N + len(node0)) // TODO: Could be cleaned by using a byte buffer, but is it faster?
				copy(bytesToHash, node0)
				copy(bytesToHash[parameters.N:], auth[j * parameters.N:(j+1)*parameters.N])
				
				node1 = hashFunc.H(PKseed, adrs, bytesToHash)
				
			} else {
				adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)

				bytesToHash := make([]byte, parameters.N + len(node0)) // TODO: Could be cleaned by using a byte buffer, but is it faster?
				copy(bytesToHash, auth[j * parameters.N:(j+1)*parameters.N])
				copy(bytesToHash[parameters.N:], node0)

				node1 = hashFunc.H(PKseed, adrs, bytesToHash)
			}
			
			node0 = node1
		}
		copy(root[i * parameters.N:], node0)
	}
	forsPKadrs := adrs.Copy()
	forsPKadrs.SetType(address.FORS_ROOTS)
	forsPKadrs.SetKeyPairAddress(adrs.GetKeyPairAddress())
	pk := hashFunc.T_l(PKseed, forsPKadrs, root)

	return pk
}