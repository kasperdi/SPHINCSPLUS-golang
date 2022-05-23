package tweakable

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/util"
)

// Test of MGF1-SHA256
func TestMgf1Sha256(t *testing.T) {
	result := hex.EncodeToString(mgf1sha256([]byte("bar"), 50))
	expected := "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1"
	if expected != result {
		t.Errorf("Expected: %s, but got %s", expected, result)
	}
	result2 := hex.EncodeToString(mgf1sha256([]byte("placeholder"), 42))
	expected2 := "1dee959de5c4caf4a2295477c4c505394f13ed78066dde0cd77912872e66552db66abc55d72b67c51d93"
	if expected2 != result2 {
		t.Errorf("Expected: %s, but got %s", expected2, result2)
	}
	result3 := hex.EncodeToString(mgf1sha256([]byte("test"), 10))
	expected3 := "9134a6432bb8da899b90"
	if expected3 != result3 {
		t.Errorf("Expected: %s, but got %s", expected3, result3)
	}
}

// Test of ADRS compression ADRSc for ADRS type 0
func TestCompressADRSType0(t *testing.T) {

	layerAddress := [4]byte{0, 1, 2, 3}
	treeAddress := [12]byte{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	var typ [4]byte
	copy(typ[:], util.ToByte(0, 4)) // Type 0 corresponds to a WOTS+ hash address
	keyPairAddress := [4]byte{20, 21, 22, 23}
	chainAddress := [4]byte{24, 25, 26, 27}
	hashAddress := [4]byte{28, 29, 30, 31}

	adrs := address.ADRS{
		LayerAddress:   layerAddress,
		TreeAddress:    treeAddress,
		Type:           typ,
		KeyPairAddress: keyPairAddress,
		ChainAddress:   chainAddress,
		HashAddress:    hashAddress,
	}
	adrsc := compressADRS(&adrs)

	expected := [22]byte{3, 8, 9, 10, 11, 12, 13, 14, 15, 0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	if !bytes.Equal(adrsc, expected[:]) {
		t.Errorf("Compression of type 0 ADRS did not result in the correct bytes")
		fmt.Println(adrsc)
		fmt.Println(expected[:])
	}

}

func TestCompressADRSType1(t *testing.T) {

	layerAddress := [4]byte{0, 1, 2, 3}
	treeAddress := [12]byte{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	var typ [4]byte
	copy(typ[:], util.ToByte(1, 4))
	keyPairAddress := [4]byte{20, 21, 22, 23}

	adrs := address.ADRS{
		LayerAddress:   layerAddress,
		TreeAddress:    treeAddress,
		Type:           typ,
		KeyPairAddress: keyPairAddress,
	}
	adrsc := compressADRS(&adrs)

	expected := [22]byte{3, 8, 9, 10, 11, 12, 13, 14, 15, 1, 20, 21, 22, 23, 0, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(adrsc, expected[:]) {
		t.Errorf("Compression of type 0 ADRS did not result in the correct bytes")
		fmt.Println(adrsc)
		fmt.Println(expected[:])
	}

}
