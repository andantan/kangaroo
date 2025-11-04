package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/andantan/kangaroo/crypto"
	_ "github.com/andantan/kangaroo/crypto/all"
	"github.com/andantan/kangaroo/registry"
	"log"
	"os"
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
	addrAlgo := flag.String("addr-algo", defaultAddressAlgorithm, "Address derivation algorithm (e.g., keccak256, sha256, ripemd160)")
	outputFile := flag.String("o", "wallet.json", "Output file name for the generated key pair")
	flag.Parse()

	keySuite, err := registry.GetKeySuite(*keyAlgo)
	if err != nil {
		log.Fatalf("FATAL: Unsupported key algorithm: %v", err)
	}
	addressSuite, err := registry.GetAddressSuite(*addrAlgo)
	if err != nil {
		log.Fatalf("FATAL: Unsupported address algorithm: %v", err)
	}

	log.Printf("Generating a new key pair using '%s' algorithm...", *keyAlgo)

	privateKey, err := keySuite.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("FATAL: Failed to generate private key: %v", err)
	}
	wrappedPrivateKeyString, err := crypto.WrapPrivateKeyToString(privateKey)
	if err != nil {
		log.Fatalf("FATAL: Failed to wrap private key: %v", err)
	}

	publicKey := privateKey.PublicKey()
	wrappedPublicKeyString, err := crypto.WrapPublicKeyToString(publicKey)
	if err != nil {
		log.Fatalf("FATAL: Failed to wrap public key: %v", err)
	}

	address := publicKey.Address(addressSuite.Deriver())
	wrappedAddressString, err := crypto.WrapAddressToString(address)
	if err != nil {
		log.Fatalf("FATAL: Failed to wrap address: %v", err)
	}

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
	fmt.Printf("%-19s \t%s\n", "Key Algorithm:", privateKey.Type())
	fmt.Printf("%-19s \t%s\n", "Private Key (Raw):", privateKey.String())
	fmt.Printf("%-19s \t%s\n", "Private Key (Wrapped):", wrappedPrivateKeyString)
	fmt.Printf("%-19s \t%s\n", "Public Key (Raw):", publicKey.String())
	fmt.Printf("%-19s \t%s\n", "Public Key (Wrapped):", wrappedPublicKeyString)
	fmt.Printf("%-19s \t%s\n", "Address Algorithm:", address.Type())
	fmt.Printf("%-19s \t%s\n", "Address (Raw):", address.String())
	fmt.Printf("%-19s \t%s\n", "Address (Wrapped):", wrappedAddressString)
	fmt.Printf("\n✅ Key pair successfully saved to '%s'\n", *outputFile)
}
