package registry

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	"log"
	"sync"
)

// ============================================================================================================
//
//	KEY SUITE REGISTRY
//
// ============================================================================================================
var keySuiteRegistry = make(map[string]key.KeySuite)
var keySuiteLock = &sync.RWMutex{}

func RegisterKeySuite(s key.KeySuite) {
	keySuiteLock.Lock()
	defer keySuiteLock.Unlock()

	name := s.Type()
	if _, exists := keySuiteRegistry[name]; exists {
		panic("crypto suite already registered: " + name)
	}
	keySuiteRegistry[name] = s
	log.Printf("[Registry] Registered Key Suite: name='%s', type=%T", name, s)
}

func GetKeySuite(name string) (key.KeySuite, error) {
	keySuiteLock.RLock()
	defer keySuiteLock.RUnlock()

	suite, ok := keySuiteRegistry[name]
	if !ok {
		return nil, fmt.Errorf("crypto suite not found: %s", name)
	}
	return suite, nil
}
