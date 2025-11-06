package registry

import (
	"fmt"
	"github.com/andantan/kangaroo/core/block"
	"log"
	"sync"
)

// ============================================================================================================
//
//	BODY SUITE REGISTRY
//
// ============================================================================================================
var bodySuiteRegistry = make(map[string]block.BodySuite)
var bodySuitelock = &sync.RWMutex{}

func RegistryBodySuite(s block.BodySuite) {
	bodySuitelock.Lock()
	defer bodySuitelock.Unlock()
	name := s.Type()
	if _, exists := bodySuiteRegistry[name]; exists {
		panic("body suite already registered: " + name)
	}
	bodySuiteRegistry[name] = s
	log.Printf("[Registry] Registered Body Suite: name='%s', type=%T", name, s)
}

func GetBodySuite(name string) (block.BodySuite, error) {
	bodySuitelock.RLock()
	defer bodySuitelock.RUnlock()
	suite, ok := bodySuiteRegistry[name]
	if !ok {
		return nil, fmt.Errorf("body suite not found: %s", name)
	}
	return suite, nil
}
