package registry

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"log"
	"sync"
)

// ============================================================================================================
//
//	ADDRESS SUITE REGISTRY
//
// ============================================================================================================
var addressSuiteRegistry = make(map[string]hash.AddressSuite)
var addressSuiteLock = &sync.RWMutex{}

func RegisterAddressSuite(s hash.AddressSuite) {
	addressSuiteLock.Lock()
	defer addressSuiteLock.Unlock()
	name := s.Type()
	if _, exists := addressSuiteRegistry[name]; exists {
		panic("hash suite already registered: " + name)
	}
	addressSuiteRegistry[name] = s
	log.Printf("[Registry] Registered Address Suite: name='%s', type=%T", name, s)
}

func GetAddressSuite(name string) (hash.AddressSuite, error) {
	addressSuiteLock.RLock()
	defer addressSuiteLock.RUnlock()
	suite, ok := addressSuiteRegistry[name]
	if !ok {
		return nil, fmt.Errorf("hash suite not found: %s", name)
	}
	return suite, nil
}
