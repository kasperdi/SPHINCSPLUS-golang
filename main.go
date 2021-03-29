package main

import (
	"crypto/rand"
	"fmt"
	"./hypertree"
)

func main() {
	fmt.Println("PLACEHOLDER")
	hypertree.Ht_PKgen(nil, nil)

	message := make([]byte, 32)
	rand.Read(message)
	messageFake := make([]byte, 32)
	rand.Read(messageFake)
	SKseed := make([]byte, 32)
	rand.Read(SKseed)
	PKseed := make([]byte, 32)
	rand.Read(SKseed)

	PK := hypertree.Ht_PKgen(SKseed, PKseed)

	signature := hypertree.Ht_sign(message, SKseed, PKseed, 0, 0)

	fmt.Println(hypertree.Ht_verify(message, signature, PKseed, 0, 0, PK))


	
}