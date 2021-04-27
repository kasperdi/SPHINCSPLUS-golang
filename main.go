package main

import (
	"fmt"
	"encoding/hex"
	"./address"
	"./fors"
)

func main() {
	//msg := "Nola pustulata, the sharp-blotched nola, is a species of nolid moth in the family Nolidae."
	PKseed := make([]byte, 32)
	SKseed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		PKseed[i] = byte(i);
	}

	var adrs address.ADRS
	adrs.SetType(address.FORS_TREE)


	test := fors.Fors_treehash(SKseed, 14080, 3, PKseed, &adrs)
	

	//msgAsBytes := []byte(msg)

	fmt.Println(test)
	fmt.Println(hex.EncodeToString(test))




	
}