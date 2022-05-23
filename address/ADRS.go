package address

import (
	"encoding/binary"

	"github.com/kasperdi/SPHINCSPLUS-golang/util"
)

const (
	// ADRS types
	WOTS_HASH  = 0
	WOTS_PK    = 1
	TREE       = 2
	FORS_TREE  = 3
	FORS_ROOTS = 4
)

type ADRS struct {
	LayerAddress   [4]byte
	TreeAddress    [12]byte
	Type           [4]byte
	KeyPairAddress [4]byte
	TreeHeight     [4]byte
	TreeIndex      [4]byte
	ChainAddress   [4]byte
	HashAddress    [4]byte
}

func (adrs *ADRS) Copy() *ADRS {
	newADRS := new(ADRS)
	newADRS.LayerAddress = adrs.LayerAddress
	newADRS.TreeAddress = adrs.TreeAddress
	newADRS.Type = adrs.Type
	newADRS.KeyPairAddress = adrs.KeyPairAddress
	newADRS.TreeHeight = adrs.TreeHeight
	newADRS.TreeIndex = adrs.TreeIndex
	newADRS.ChainAddress = adrs.ChainAddress
	newADRS.HashAddress = adrs.HashAddress
	return newADRS
}

func (adrs *ADRS) GetBytes() []byte {
	ADRSc := make([]byte, 32)

	copy(ADRSc[0:4], adrs.LayerAddress[:])
	copy(ADRSc[4:16], adrs.TreeAddress[:])
	copy(ADRSc[16:20], adrs.Type[:])

	switch adrs.GetType() {
	case WOTS_HASH:
		copy(ADRSc[20:24], adrs.KeyPairAddress[:])
		copy(ADRSc[24:28], adrs.ChainAddress[:])
		copy(ADRSc[28:32], adrs.HashAddress[:])
	case WOTS_PK:
		copy(ADRSc[20:24], adrs.KeyPairAddress[:])
	case TREE:
		copy(ADRSc[24:28], adrs.TreeHeight[:])
		copy(ADRSc[28:32], adrs.TreeIndex[:])
	case FORS_TREE:
		copy(ADRSc[20:24], adrs.KeyPairAddress[:])
		copy(ADRSc[24:28], adrs.TreeHeight[:])
		copy(ADRSc[28:32], adrs.TreeIndex[:])
	case FORS_ROOTS:
		copy(ADRSc[20:24], adrs.KeyPairAddress[:])
	}

	return ADRSc
}

func (adrs *ADRS) SetLayerAddress(a int) {
	var layerAddress [4]byte
	copy(layerAddress[:], util.ToByte(uint64(a), 4))
	adrs.LayerAddress = layerAddress
}

func (adrs *ADRS) SetTreeAddress(a uint64) {
	var treeAddress [12]byte
	treeAddressBytes := util.ToByte(a, 12)
	copy(treeAddress[:], treeAddressBytes)
	adrs.TreeAddress = treeAddress
}

func (adrs *ADRS) SetType(a int) {
	var typ [4]byte
	copy(typ[:], util.ToByte(uint64(a), 4))
	adrs.Type = typ
	//Set the three last words to 0 as described in section 2.7.3
	adrs.SetKeyPairAddress(0)
	adrs.SetChainAddress(0)
	adrs.SetHashAddress(0)
	adrs.SetTreeHeight(0)
	adrs.SetTreeIndex(0)
}

func (adrs *ADRS) SetKeyPairAddress(a int) {
	var keyPairAddress [4]byte
	copy(keyPairAddress[:], util.ToByte(uint64(a), 4))
	adrs.KeyPairAddress = keyPairAddress
}

func (adrs *ADRS) SetTreeHeight(a int) {
	var treeHeight [4]byte
	copy(treeHeight[:], util.ToByte(uint64(a), 4))
	adrs.TreeHeight = treeHeight
}

func (adrs *ADRS) SetTreeIndex(a int) {
	var treeIndex [4]byte
	copy(treeIndex[:], util.ToByte(uint64(a), 4))
	adrs.TreeIndex = treeIndex
}

func (adrs *ADRS) SetChainAddress(a int) {
	var chainAddress [4]byte
	copy(chainAddress[:], util.ToByte(uint64(a), 4))
	adrs.ChainAddress = chainAddress
}

func (adrs *ADRS) SetHashAddress(a int) {
	var hashAddress [4]byte
	copy(hashAddress[:], util.ToByte(uint64(a), 4))
	adrs.HashAddress = hashAddress
}

func (adrs *ADRS) GetKeyPairAddress() int {
	keyPairAddressBytes := adrs.KeyPairAddress[:]
	keyPairAddressUint32 := binary.BigEndian.Uint32(keyPairAddressBytes)
	return int(keyPairAddressUint32)
}

func (adrs *ADRS) GetTreeIndex() int {
	treeIndexBytes := adrs.TreeIndex[:]
	treeIndexUint32 := binary.BigEndian.Uint32(treeIndexBytes)
	return int(treeIndexUint32)
}

func (adrs *ADRS) GetTreeHeight() int {
	treeHeightBytes := adrs.TreeHeight[:]
	treeHeightUint32 := binary.BigEndian.Uint32(treeHeightBytes)
	return int(treeHeightUint32)
}

func (adrs *ADRS) GetType() int {
	typeBytes := adrs.Type[:]
	typeUint32 := binary.BigEndian.Uint32(typeBytes)
	return int(typeUint32)
}

func (adrs *ADRS) GetTreeAddress() int {
	treeAddressBytes := adrs.TreeAddress[:]
	treeAddressUint64 := binary.BigEndian.Uint64(treeAddressBytes)
	return int(treeAddressUint64)
}
