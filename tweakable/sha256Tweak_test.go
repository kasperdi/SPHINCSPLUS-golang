package tweakable

import (
	"testing"
	"encoding/hex"
	"../address"
	"fmt"
)

// Test of MGF1-SHA256
func TestMgf1Sha256(t *testing.T) { //TODO: MORE TEST CASES, GENERATE DATA USING PYTHON IMPLEMENTATION
	result := hex.EncodeToString(mgf1sha256([]byte("bar"), 50))
	expected := "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1"
	if (expected != result) {
		t.Errorf("Expected: %s, but got %s", expected, result)
	}
	

}

/* // Test of ADRS compression ADRSc
func TestCompressADRS(t *testing.T) {
	
	layerAddress := [4]byte{0, 1, 2, 3}

	treeAddress := [12]byte{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	typ := int32(0)							// Type 0 corresponds to a WOTS+ hash address

	keyPairAddress := [4]byte{20, 21, 22, 23}

	chainAddress := [4]byte{24, 25, 26, 27}

	hashAddress := int32(12345)

	adrs := address.ADRS{LayerAddress: layerAddress,
		TreeAddress: treeAddress,
		Type: typ,
		KeyPairAddress: keyPairAddress,
		ChainAddress: chainAddress,
		HashAddress: hashAddress}
	adrsc := compressADRS(&adrs)
	fmt.Println(adrs)
	fmt.Println(adrsc)
	t.Errorf("testing")
	
} */