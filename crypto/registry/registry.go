package registry

import (
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	"log"
	"sync"
)

// ============================================================================================================

var hashSuiteRegistry = make(map[string]kangaroohash.HashSuite)
var hashSuiteLock = &sync.RWMutex{}

func RegisterHashSuite(s kangaroohash.HashSuite) {
	hashSuiteLock.Lock()
	defer hashSuiteLock.Unlock()
	name := s.Type()
	if _, exists := hashSuiteRegistry[name]; exists {
		panic("hash suite already registered: " + name)
	}
	hashSuiteRegistry[name] = s
	log.Printf("[Registry] Registered Hash Suite: name='%s', type=%T", name, s)
}

func GetHashSuite(name string) (kangaroohash.HashSuite, error) {
	hashSuiteLock.RLock()
	defer hashSuiteLock.RUnlock()
	suite, ok := hashSuiteRegistry[name]
	if !ok {
		return nil, fmt.Errorf("hash suite not found: %s", name)
	}
	return suite, nil
}

// ============================================================================================================
// ============================================================================================================

var addressSuiteRegistry = make(map[string]kangaroohash.AddressSuite)
var addressSuiteLock = &sync.RWMutex{}

func RegisterAddressSuite(s kangaroohash.AddressSuite) {
	addressSuiteLock.Lock()
	defer addressSuiteLock.Unlock()
	name := s.Type()
	if _, exists := addressSuiteRegistry[name]; exists {
		panic("hash suite already registered: " + name)
	}
	addressSuiteRegistry[name] = s
	log.Printf("[Registry] Registered Address Suite: name='%s', type=%T", name, s)
}

func GetAddressSuite(name string) (kangaroohash.AddressSuite, error) {
	addressSuiteLock.RLock()
	defer addressSuiteLock.RUnlock()
	suite, ok := addressSuiteRegistry[name]
	if !ok {
		return nil, fmt.Errorf("hash suite not found: %s", name)
	}
	return suite, nil
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
