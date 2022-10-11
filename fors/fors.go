package fors

import (
	"math"

	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/util"
)

type FORSSignature struct {
	Forspkauth []*TreePKAUTH
}

type TreePKAUTH struct {
	PrivateKeyValue []byte
	AUTH            []byte
}

func (s *FORSSignature) GetSK(index int) []byte {
	return s.Forspkauth[index].PrivateKeyValue
}

func (s *FORSSignature) GetAUTH(index int) []byte {
	return s.Forspkauth[index].AUTH
}

func Fors_treehash(params *parameters.Parameters, SKseed []byte, startIndex int, targetNodeHeight int, PKseed []byte, adrs *address.ADRS) []byte {
	if startIndex%(1<<targetNodeHeight) != 0 {
		return nil
	}

	stack := util.Stack{}

	for i := 0; i < int(math.Pow(2, float64(targetNodeHeight))); i++ {
		adrs.SetTreeHeight(0)
		adrs.SetTreeIndex(startIndex + i)
		sk := params.Tweak.PRF(SKseed, adrs)
		node := params.Tweak.F(PKseed, adrs, sk)

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

func Fors_PKgen(params *parameters.Parameters, SKseed []byte, PKseed []byte, adrs *address.ADRS) []byte {
	forsPKadrs := adrs.Copy()
	root := make([]byte, params.K*params.N)

	for i := 0; i < params.K; i++ {
		copy(root[i*params.N:], Fors_treehash(params, SKseed, i*params.T, params.A, PKseed, adrs))
	}
	forsPKadrs.SetType(address.FORS_ROOTS)
	forsPKadrs.SetKeyPairAddress(adrs.GetKeyPairAddress())
	pk := params.Tweak.T_l(PKseed, forsPKadrs, root)

	return pk
}

// Taken from reference implementation and converted into Go code
func message_to_indices(M []byte, k int, a int) []int {
	offset := 0
	indices := make([]int, k)

	for i := 0; i < k; i++ {
		indices[i] = 0
		for j := 0; j < a; j++ {
			indices[i] ^= ((int(M[offset>>3]) >> (offset & 0x7)) & 0x1) << j
			offset++
		}
	}
	return indices
}

func Fors_sign(params *parameters.Parameters, M []byte, SKseed []byte, PKseed []byte, adrs *address.ADRS) *FORSSignature {
	// compute signature elements
	SIG_FORS := new(FORSSignature)

	for i := 0; i < params.K; i++ {
		// get next index
		indices := message_to_indices(M, params.K, params.A)

		// pick private key element
		adrs.SetTreeHeight(0)
		adrs.SetTreeIndex(i*params.T + indices[i])
		PKElement := params.Tweak.PRF(SKseed, adrs)

		AUTH := make([]byte, params.A*params.N)
		for j := 0; j < params.A; j++ {
			s := int(math.Floor(float64(indices[i])/math.Pow(2, float64(j)))) ^ 1
			test := Fors_treehash(params, SKseed, i*params.T+s*int(math.Pow(2, float64(j))), j, PKseed, adrs)

			copy(AUTH[j*params.N:], test)
		}

		SIG_FORS.Forspkauth = append(SIG_FORS.Forspkauth, &TreePKAUTH{PKElement, AUTH})
	}
	return SIG_FORS
}

func Fors_pkFromSig(params *parameters.Parameters, SIG_FORS *FORSSignature, M []byte, PKseed []byte, adrs *address.ADRS) []byte {
	root := make([]byte, params.K*params.N)
	for i := 0; i < params.K; i++ {
		// get next index
		indices := message_to_indices(M, params.K, params.A)

		// compute leaf
		sk := SIG_FORS.GetSK(i)
		adrs.SetTreeHeight(0)
		adrs.SetTreeIndex(i*params.T + indices[i])

		node0 := params.Tweak.F(PKseed, adrs, sk)
		var node1 []byte

		// compute root from leaf and AUTH
		auth := SIG_FORS.GetAUTH(i)

		adrs.SetTreeIndex(i*params.T + indices[i])
		for j := 0; j < params.A; j++ {
			adrs.SetTreeHeight(j + 1)

			if int(math.Floor(float64(indices[i])/math.Pow(2, float64(j))))%2 == 0 {
				adrs.SetTreeIndex(adrs.GetTreeIndex() / 2)

				bytesToHash := make([]byte, params.N+len(node0))
				copy(bytesToHash, node0)
				copy(bytesToHash[params.N:], auth[j*params.N:(j+1)*params.N])

				node1 = params.Tweak.H(PKseed, adrs, bytesToHash)

			} else {
				adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)

				bytesToHash := make([]byte, params.N+len(node0))
				copy(bytesToHash, auth[j*params.N:(j+1)*params.N])
				copy(bytesToHash[params.N:], node0)

				node1 = params.Tweak.H(PKseed, adrs, bytesToHash)
			}

			node0 = node1
		}
		copy(root[i*params.N:], node0)
	}
	forsPKadrs := adrs.Copy()
	forsPKadrs.SetType(address.FORS_ROOTS)
	forsPKadrs.SetKeyPairAddress(adrs.GetKeyPairAddress())
	pk := params.Tweak.T_l(PKseed, forsPKadrs, root)

	return pk
}
