package registry

import (
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	"log"
	"sync"
)

// ============================================================================================================

var hashDeriverRegistry = make(map[string]kangaroohash.HashDeriver)
var hashDeriverLock = &sync.RWMutex{}

func RegisterHashDeriver(d kangaroohash.HashDeriver) {
	hashDeriverLock.Lock()
	defer hashDeriverLock.Unlock()
	if _, exists := hashDeriverRegistry[d.Type()]; exists {
		panic("hash deriver already registered: " + d.Type())
	}
	hashDeriverRegistry[d.Type()] = d
	log.Printf("[Registry] Registered Hash Deriver: name='%s', type=%T", d.Type(), d)
}

func GetHashDeriver(name string) (kangaroohash.HashDeriver, error) {
	hashDeriverLock.RLock()
	defer hashDeriverLock.RUnlock()
	d, ok := hashDeriverRegistry[name]
	if !ok {
		return nil, fmt.Errorf("hash deriver not found: %s", name)
	}
	return d, nil
}

// ============================================================================================================
// ============================================================================================================

var addressDeriverRegistry = make(map[string]kangaroohash.AddressDeriver)
var addressDeriverLock = &sync.RWMutex{}

func RegisterAddressDeriver(d kangaroohash.AddressDeriver) {
	addressDeriverLock.Lock()
	defer addressDeriverLock.Unlock()
	if _, exists := addressDeriverRegistry[d.Type()]; exists {
		panic("hash deriver already registered: " + d.Type())
	}
	addressDeriverRegistry[d.Type()] = d
	log.Printf("[Registry] Registered Address Deriver: name='%s', type=%T", d.Type(), d)
}

func GetAddressDeriver(name string) (kangaroohash.AddressDeriver, error) {
	addressDeriverLock.RLock()
	defer addressDeriverLock.RUnlock()
	d, ok := addressDeriverRegistry[name]
	if !ok {
		return nil, fmt.Errorf("hash deriver not found: %s", name)
	}
	return d, nil
}

// ============================================================================================================
// ============================================================================================================

var keySuiteRegistry = make(map[string]kangarookey.KeySuite)
var keySuiteLock = &sync.RWMutex{}

func RegisterKeySuite(s kangarookey.KeySuite) {
	keySuiteLock.Lock()
	defer keySuiteLock.Unlock()

	name := s.Type()
	if _, exists := keySuiteRegistry[name]; exists {
		panic("crypto suite already registered: " + name)
	}
	keySuiteRegistry[name] = s
	log.Printf("[Registry] Registered Key Suite: name='%s', type=%T", name, s)
}

func GetKeySuite(name string) (kangarookey.KeySuite, error) {
	keySuiteLock.RLock()
	defer keySuiteLock.RUnlock()

	suite, ok := keySuiteRegistry[name]
	if !ok {
		return nil, fmt.Errorf("crypto suite not found: %s", name)
	}
	return suite, nil
}

// ============================================================================================================
