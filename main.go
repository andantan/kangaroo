package main

import (
	"fmt"
	"log"

	kangaroocrypto "github.com/andantan/kangaroo/crypto"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarookeccak256 "github.com/andantan/kangaroo/crypto/hash/keccak256"
	kangarooripemd160 "github.com/andantan/kangaroo/crypto/hash/ripemd160"
	kangaroosha256 "github.com/andantan/kangaroo/crypto/hash/sha256"
	kangaroosecp256k1 "github.com/andantan/kangaroo/crypto/key/ecdsa/secp256k1"
	kangaroosecp256r1 "github.com/andantan/kangaroo/crypto/key/ecdsa/secp256r1"
	kangarooed25519 "github.com/andantan/kangaroo/crypto/key/eddsa/ed25519"
)

func setupRegistry() {
	log.Println("--- Initializing Crypto Registry ---")
	kangaroocrypto.RegisterHashDeriver(kangaroohash.Sha256Type, &kangaroosha256.Sha256HashDeriver{})
	kangaroocrypto.RegisterHashDeriver(kangaroohash.Keccak256Type, &kangarookeccak256.Keccak256HashDeriver{})

	// Address Derivers
	kangaroocrypto.RegisterAddressDeriver(kangaroohash.Sha256Type, &kangaroosha256.Sha256AddressDeriver{})
	kangaroocrypto.RegisterAddressDeriver(kangaroohash.Keccak256Type, &kangarookeccak256.Keccak256AddressDeriver{})
	kangaroocrypto.RegisterAddressDeriver(kangaroohash.Ripemd160Type, &kangarooripemd160.Ripemd160AddressDeriver{})

	// Key Suites
	kangaroocrypto.RegisterKeySuite(&kangaroosecp256r1.ECDSASecp256r1Suite{})
	kangaroocrypto.RegisterKeySuite(&kangaroosecp256k1.ECDSASecp256k1Suite{})
	kangaroocrypto.RegisterKeySuite(&kangarooed25519.EdDSAEd25519Suite{})
}

func main() {
	setupRegistry()

	fmt.Println("Hello, World!")
}
