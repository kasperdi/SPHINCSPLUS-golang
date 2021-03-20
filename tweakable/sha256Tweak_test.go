package tweakable

import (
	"testing"
	"encoding/hex"
)

// Template for test
func TestMgf1Sha256(t *testing.T) { //TODO: MORE TEST CASES, GENERATE DATA USING PYTHON IMPLEMENTATION
	result := hex.EncodeToString(mgf1sha256([]byte("bar"), 50))
	expected := "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1"
	if (expected != result) {
		t.Errorf("Expected: %s, but got %s", expected, result)
	}
	

}