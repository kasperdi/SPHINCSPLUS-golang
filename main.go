package main

import (
	"fmt"
	"./util"
)

func main() {
	fmt.Println("PLACEHOLDER")
	fmt.Println(util.ToByte(0, 64))
	test := "abcd21412"
	fmt.Println(test[0:4])
	fmt.Println(3&2)
	fmt.Println(3 << 2)
}