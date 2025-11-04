package registry

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"log"
	"sync"
)

// ============================================================================================================
//
//	HASH SUITE REGISTRY
//
// ============================================================================================================
var hashSuiteRegistry = make(map[string]hash.HashSuite)
var hashSuiteLock = &sync.RWMutex{}

func RegisterHashSuite(s hash.HashSuite) {
	hashSuiteLock.Lock()
	defer hashSuiteLock.Unlock()
	name := s.Type()
	if _, exists := hashSuiteRegistry[name]; exists {
		panic("hash suite already registered: " + name)
	}
	hashSuiteRegistry[name] = s
	log.Printf("[Registry] Registered Hash Suite: name='%s', type=%T", name, s)
}

func GetHashSuite(name string) (hash.HashSuite, error) {
	hashSuiteLock.RLock()
	defer hashSuiteLock.RUnlock()
	suite, ok := hashSuiteRegistry[name]
	if !ok {
		return nil, fmt.Errorf("hash suite not found: %s", name)
	}
	return suite, nil
}
