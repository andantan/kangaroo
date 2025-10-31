package crypto

import (
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

type mockHashDeriver struct{}

var _ kangaroohash.HashDeriver = (*mockHashDeriver)(nil)

func (m *mockHashDeriver) Derive(_ []byte) kangaroohash.Hash { return nil }

func TestHashDeriverRegistry_RegistrationAndRetrieval(t *testing.T) {
	hashDeriverRegistry = make(map[string]kangaroohash.HashDeriver)

	t.Run("should register and get a new hash deriver successfully", func(t *testing.T) {
		mock := &mockHashDeriver{}
		RegisterHashDeriver("mock-hash", mock)

		retrieved, err := GetHashDeriver("mock-hash")
		require.NoError(t, err)
		assert.Equal(t, mock, retrieved)
	})

	t.Run("should return an error for a non-existent hash deriver", func(t *testing.T) {
		_, err := GetHashDeriver("non-existent-hash")
		assert.Error(t, err)
	})

	t.Run("should panic on duplicate hash deriver registration", func(t *testing.T) {
		mock := &mockHashDeriver{}
		RegisterHashDeriver("duplicate-hash", mock)

		assert.Panics(t, func() {
			RegisterHashDeriver("duplicate-hash", mock)
		})
	})
}

func TestHashDeriverRegistry_Concurrency(t *testing.T) {
	hashDeriverRegistry = make(map[string]kangaroohash.HashDeriver)
	var wg sync.WaitGroup
	numGoroutines := 100

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("concurrent-hash-%d", i)
			mock := &mockHashDeriver{}
			RegisterHashDeriver(name, mock)

			retrieved, err := GetHashDeriver(name)
			assert.NoError(t, err)
			assert.NotNil(t, retrieved)
		}(i)
	}

	wg.Wait()
	assert.Equal(t, numGoroutines, len(hashDeriverRegistry))
}

type mockAddressDeriver struct{}

var _ kangaroohash.AddressDeriver = (*mockAddressDeriver)(nil)

func (m *mockAddressDeriver) Derive(_ []byte) kangaroohash.Address { return nil }

func TestAddressDeriverRegistry_RegistrationAndRetrieval(t *testing.T) {
	addressDeriverRegistry = make(map[string]kangaroohash.AddressDeriver)

	t.Run("should register and get a new address deriver successfully", func(t *testing.T) {
		mock := &mockAddressDeriver{}
		RegisterAddressDeriver("mock-address", mock)

		retrieved, err := GetAddressDeriver("mock-address")
		require.NoError(t, err)
		assert.Equal(t, mock, retrieved)
	})

	t.Run("should return an error for a non-existent address deriver", func(t *testing.T) {
		_, err := GetAddressDeriver("non-existent-address")
		assert.Error(t, err)
	})

	t.Run("should panic on duplicate address deriver registration", func(t *testing.T) {
		mock := &mockAddressDeriver{}
		RegisterAddressDeriver("duplicate-address", mock)

		assert.Panics(t, func() {
			RegisterAddressDeriver("duplicate-address", mock)
		})
	})
}

func TestAddressDeriverRegistry_Concurrency(t *testing.T) {
	addressDeriverRegistry = make(map[string]kangaroohash.AddressDeriver)
	var wg sync.WaitGroup
	numGoroutines := 100

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("concurrent-address-%d", i)
			mock := &mockAddressDeriver{}
			RegisterAddressDeriver(name, mock)

			retrieved, err := GetAddressDeriver(name)
			assert.NoError(t, err)
			assert.NotNil(t, retrieved)
		}(i)
	}

	wg.Wait()
	assert.Equal(t, numGoroutines, len(addressDeriverRegistry))
}

type mockSuite struct {
	suiteType string
}

var _ kangarookey.KeySuite = (*mockSuite)(nil)

func (m *mockSuite) Type() string                                                 { return m.suiteType }
func (m *mockSuite) GeneratePrivateKey() (kangarookey.PrivateKey, error)          { return nil, nil }
func (m *mockSuite) PrivateKeyFromBytes(_ []byte) (kangarookey.PrivateKey, error) { return nil, nil }
func (m *mockSuite) PublicKeyFromBytes(_ []byte) (kangarookey.PublicKey, error)   { return nil, nil }
func (m *mockSuite) SignatureFromBytes(_ []byte) (kangarookey.Signature, error)   { return nil, nil }

func TestRegisterAndGetKeySuite(t *testing.T) {
	keySuiteRegistry = make(map[string]kangarookey.KeySuite)

	t.Run("should register and get a new suite successfully", func(t *testing.T) {
		mock := &mockSuite{suiteType: "mock-suite-1"}
		RegisterKeySuite(mock)

		retrieved, err := GetKeySuite("mock-suite-1")
		require.NoError(t, err)
		assert.Equal(t, mock, retrieved)
	})

	t.Run("should return an error for a non-existent suite", func(t *testing.T) {
		_, err := GetKeySuite("non-existent-suite")
		assert.Error(t, err)
	})

	t.Run("should panic on duplicate registration", func(t *testing.T) {
		mock := &mockSuite{suiteType: "duplicate-suite"}
		RegisterKeySuite(mock)

		assert.Panics(t, func() {
			RegisterKeySuite(mock)
		})
	})
}

func TestRegistry_Concurrency(t *testing.T) {
	keySuiteRegistry = make(map[string]kangarookey.KeySuite)

	var wg sync.WaitGroup
	numGoroutines := 100

	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(i int) {
			defer wg.Done()
			suiteName := fmt.Sprintf("concurrent-suite-%d", i)
			mock := &mockSuite{suiteType: suiteName}
			RegisterKeySuite(mock)

			retrieved, err := GetKeySuite(suiteName)
			assert.NoError(t, err)
			assert.NotNil(t, retrieved)
		}(i)
	}

	wg.Wait()

	assert.Equal(t, numGoroutines, len(keySuiteRegistry))
}
