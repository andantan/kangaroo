package main

import (
	"encoding/json"
	"flag"
	"fmt"
	kangaroocrypto "github.com/andantan/kangaroo/crypto/registry"
	"log"
	"os"

	_ "github.com/andantan/kangaroo/crypto/all"
)

type KeyFile struct {
	KeyAlgorithm  string `json:"key_algorithm"`
	PrivateKey    string `json:"private_key"`
	PublicKey     string `json:"public_key"`
	AddrAlgorithm string `json:"addr_Algorithm"`
	Address       string `json:"address"`
}

const defaultKeyAlgorithm = "ecdsa-secp256k1"
const defaultAddressAlgorithm = "keccak256"

// e.g., make key-gen ARGS="--key-algo=eddsa-ed25519 --addr-algo=keccak256 -o mykey.json"
func main() {
	keyAlgo := flag.String("key-algo", defaultKeyAlgorithm, "Key algorithm to use (e.g., ecdsa-secp256[k|r]1, eddsa-ed25519)")
	addrAlgo := flag.String("addr-algo", defaultAddressAlgorithm, "Address derivation algorithm (e.g., keccak256)")
	outputFile := flag.String("o", "wallet.json", "Output file name for the generated key pair")
	flag.Parse()

	keySuite, err := kangaroocrypto.GetKeySuite(*keyAlgo)
	if err != nil {
		log.Fatalf("FATAL: Unsupported key algorithm: %v", err)
	}
	addressDeriver, err := kangaroocrypto.GetAddressDeriver(*addrAlgo)
	if err != nil {
		log.Fatalf("FATAL: Unsupported address algorithm: %v", err)
	}

	log.Printf("Generating a new key pair using '%s' algorithm...", *keyAlgo)

	privateKey, err := keySuite.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("FATAL: Failed to generate private key: %v", err)
	}
	publicKey := privateKey.PublicKey()
	address := publicKey.Address(addressDeriver)

	keyFile := KeyFile{
		KeyAlgorithm:  privateKey.Type(),
		PrivateKey:    privateKey.String(),
		PublicKey:     publicKey.String(),
		AddrAlgorithm: address.Type(),
		Address:       address.String(),
	}

	jsonData, err := json.MarshalIndent(keyFile, "", "  ")
	if err != nil {
		log.Fatalf("FATAL: Failed to marshal key data to JSON: %v", err)
	}

	err = os.WriteFile(*outputFile, jsonData, 0644)
	if err != nil {
		log.Fatalf("FATAL: Failed to write key file: %v", err)
	}

	fmt.Println("\n--- 🔑 Key Generation Successful ---")
	fmt.Printf("KeyAlgorithm: \t%s\n", privateKey.Type())
	fmt.Printf("Private Key: \t%s\n", privateKey.String())
	fmt.Printf("Public Key: \t%s\n", publicKey.String())
	fmt.Printf("AddrAlgorithm: \t%s\n", address.Type())
	fmt.Printf("Address: \t%s\n", address.String())
	fmt.Printf("\n✅ Key pair successfully saved to '%s'\n", *outputFile)
}
