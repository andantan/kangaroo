package all

import (
	_ "github.com/andantan/kangaroo/crypto/hash/blake/blake2b256"
	_ "github.com/andantan/kangaroo/crypto/hash/ripemd/ripemd160"
	_ "github.com/andantan/kangaroo/crypto/hash/sha/keccak256"
	_ "github.com/andantan/kangaroo/crypto/hash/sha/sha256"
	_ "github.com/andantan/kangaroo/crypto/hash/sha/sha3"
	_ "github.com/andantan/kangaroo/crypto/hash/zk/mimcbn254"
	_ "github.com/andantan/kangaroo/crypto/hash/zk/poseidonbn254"
	_ "github.com/andantan/kangaroo/crypto/key/ecdsa/secp256k1"
	_ "github.com/andantan/kangaroo/crypto/key/ecdsa/secp256r1"
	_ "github.com/andantan/kangaroo/crypto/key/eddsa/ed25519"
	_ "github.com/andantan/kangaroo/crypto/key/eddsa/ed448"
	_ "github.com/andantan/kangaroo/crypto/key/schnorr/secp256k1"
)
