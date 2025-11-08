package registry

import (
	"fmt"
	"github.com/andantan/kangaroo/core/block"
	"log"
	"sync"
)

// ============================================================================================================
//
//	ATTESTATION SUITE REGISTRY
//
// ============================================================================================================
var attestationSuiteRegistry = make(map[string]block.AttestationSuite)
var attestationSuiteLock = &sync.RWMutex{}

func RegistryAttestationSuite(s block.AttestationSuite) {
	attestationSuiteLock.Lock()
	defer attestationSuiteLock.Unlock()
	name := s.Type()
	if _, exists := attestationSuiteRegistry[name]; exists {
		panic("attestation suite already registered: " + name)
	}
	attestationSuiteRegistry[name] = s
	log.Printf("[Registry] Registered Attestation Suite: name='%s', type=%T", name, s)
}

func GetAttestationSuite(name string) (block.AttestationSuite, error) {
	attestationSuiteLock.RLock()
	defer attestationSuiteLock.RUnlock()
	suite, ok := attestationSuiteRegistry[name]
	if !ok {
		return nil, fmt.Errorf("attestation suite not found: %s", name)
	}
	return suite, nil
}
