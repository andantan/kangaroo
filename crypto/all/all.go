package all

import (
	_ "github.com/andantan/kangaroo/crypto/hash"
	_ "github.com/andantan/kangaroo/crypto/hash/keccak256"
	_ "github.com/andantan/kangaroo/crypto/hash/ripemd160"
	_ "github.com/andantan/kangaroo/crypto/hash/sha256"
	_ "github.com/andantan/kangaroo/crypto/key"
	_ "github.com/andantan/kangaroo/crypto/key/ecdsa/secp256k1"
	_ "github.com/andantan/kangaroo/crypto/key/ecdsa/secp256r1"
	_ "github.com/andantan/kangaroo/crypto/key/eddsa/ed25519"
)
