package main

import (
	"fmt"
	"crypto/rand"
	"bytes"
	"./xmss"
	"./address"
)

func main() {
	//fmt.Println("PLACEHOLDER")
	//fmt.Println(util.ToByte(0, 64))
	//test := "abcd21412"
	//fmt.Println(test[0:4])
	//fmt.Println(3&2)
	//fmt.Println(3 << 2)

	SKseed := make([]byte, 32)
	rand.Read(SKseed)
	PKseed := make([]byte, 32)
	rand.Read(PKseed)
	message := make([]byte, 32)
	rand.Read(message)

	var adrs address.ADRS

	PK := xmss.Xmss_PKgen(SKseed, PKseed, &adrs)
	fmt.Println("Real PK")
	fmt.Println(PK)


	var adrs2 address.ADRS

	var adrs3 address.ADRS

	signature := xmss.Xmss_sign(message, SKseed, 0, PKseed, &adrs2)

	pkFromSig := xmss.Xmss_pkFromSig(0, signature, message, PKseed, &adrs3)
	fmt.Println("Calculated PK")
	fmt.Println(pkFromSig)
	
	fmt.Println(bytes.Equal(pkFromSig, PK))

}