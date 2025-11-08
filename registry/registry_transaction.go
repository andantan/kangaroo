package registry

import (
	"fmt"
	"github.com/andantan/kangaroo/core/transaction"
	"log"
	"sync"
)

// ============================================================================================================
//
//	TRANSACTION SUITE REGISTRY
//
// ============================================================================================================
var transactionSuiteRegistry = make(map[string]transaction.TransactionSuite)
var transactionSuiteLock = &sync.RWMutex{}

func RegistryTransactionSuite(s transaction.TransactionSuite) {
	transactionSuiteLock.Lock()
	defer transactionSuiteLock.Unlock()
	name := s.Type()
	if _, exists := transactionSuiteRegistry[name]; exists {
		panic("transaction suite already registered: " + name)
	}
	transactionSuiteRegistry[name] = s
	log.Printf("[Registry] Registered Transaction Suite: name='%s', type=%T", name, s)
}

func GetTransactionSuite(name string) (transaction.TransactionSuite, error) {
	transactionSuiteLock.RLock()
	defer transactionSuiteLock.RUnlock()
	suite, ok := transactionSuiteRegistry[name]
	if !ok {
		return nil, fmt.Errorf("transaction suite not found: %s", name)
	}
	return suite, nil
}
