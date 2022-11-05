package main

import (
	"fmt"
	"github.com/kinyoubenkyokai/yuberify/lib"
)

func main() {
	// set data text
	ybk := lib.NewSignPin()
	out, err := ybk.VerifyByYubikey([]byte("aaa"), int32(123456))
	if err != nil {
		panic(err)
	}
	fmt.Println(out)
}
