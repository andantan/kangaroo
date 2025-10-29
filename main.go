package main

import (
	"fmt"

	_ "github.com/andantan/kangaroo/crypto/hash/keccak256"
	_ "github.com/andantan/kangaroo/crypto/hash/ripemd160"
	_ "github.com/andantan/kangaroo/crypto/hash/sha256"

	_ "github.com/andantan/kangaroo/crypto/key/ecdsa/p256"
	_ "github.com/andantan/kangaroo/crypto/key/ecdsa/secp256k1"
	_ "github.com/andantan/kangaroo/crypto/key/eddsa/ed25519"
)

func main() {
	fmt.Println("Hello, World!")
}
