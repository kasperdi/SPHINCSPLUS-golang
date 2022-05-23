package util

import (
	"testing"
)

// Test using example in round 3 specification
func TestBase_w(t *testing.T) {
	X := []byte{0x12, 0x34} // 00010010 00110100

	result1 := Base_w(X, 16, 4)
	if len(result1) != 4 {
		t.Errorf("Wrong length of result")
	}
	for i, n := range result1 {
		if n != i+1 {
			t.Errorf("Entry %d incorrect", i)
		}
	}

	result2 := Base_w(X, 16, 3)
	if len(result2) != 3 {
		t.Errorf("Wrong length of result")
	}
	for i, n := range result2 {
		if n != i+1 {
			t.Errorf("Entry %d incorrect", i)
		}
	}

	result3 := Base_w(X, 16, 2)
	if len(result3) != 2 {
		t.Errorf("Wrong length of result")
	}
	for i, n := range result3 {
		if n != i+1 {
			t.Errorf("Entry %d incorrect", i)
		}
	}
}
