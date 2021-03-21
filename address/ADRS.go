package address

import (
	"encoding/binary"
	"../util"
)

type ADRS struct {
    LayerAddress [4]byte
	TreeAddress [12]byte
	Type [4]byte
	KeyPairAddress [4]byte
	TreeHeight [4]byte
	TreeIndex [4]byte
	ChainAddress [4]byte
	HashAddress [4]byte
}

func (adrs *ADRS) SetLayerAddress(a int) { //uint32 eller int
	var layerAddress [4]byte
	copy(layerAddress[:], util.ToByte(uint32(a), 4))	
    adrs.LayerAddress = layerAddress
}

func (adrs *ADRS) SetTreeAddress(a int) { //uint32 eller int
	var treeAddress [12]byte
	copy(treeAddress[:], util.ToByte(uint32(a), 12))
    adrs.TreeAddress = treeAddress
}

func (adrs *ADRS) SetType(a int) { //uint32 eller int
	var typ [4]byte
	copy(typ[:], util.ToByte(uint32(a), 4))
    adrs.Type = typ
}

func (adrs *ADRS) SetKeyPairAddress(a int) { //uint32 eller int
	var keyPairAddress [4]byte
	copy(keyPairAddress[:], util.ToByte(uint32(a), 4))
    adrs.KeyPairAddress = keyPairAddress
}

func (adrs *ADRS) SetTreeHeight(a int) { //uint32 eller int
	var treeHeight [4]byte
	copy(treeHeight[:], util.ToByte(uint32(a), 4))
    adrs.TreeHeight = treeHeight
}

func (adrs *ADRS) SetTreeIndex(a int) { //uint32 eller int
	var treeIndex [4]byte
	copy(treeIndex[:], util.ToByte(uint32(a), 4))
    adrs.TreeIndex = treeIndex
}

func (adrs *ADRS) SetChainAddress(a int) { //uint32 eller int
	var chainAddress [4]byte
	copy(chainAddress[:], util.ToByte(uint32(a), 4))
    adrs.ChainAddress = chainAddress
}


func (adrs *ADRS) SetHashAddress(a int) { //uint32 eller int
	var hashAddress [4]byte
	copy(hashAddress[:], util.ToByte(uint32(a), 4))
    adrs.HashAddress = hashAddress
}

func (adrs *ADRS) GetKeyPairAddress() int { //uint32 eller int
	keyPairAddressBytes := adrs.KeyPairAddress[:]
	keyPairAddressUint32 := binary.LittleEndian.Uint32(keyPairAddressBytes)
	return int(keyPairAddressUint32)
}
