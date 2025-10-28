package atomic

import (
	"math/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The test will now use `int8` as the concrete type for S,
// as it satisfies the `types.State` interface.

func TestAtomicState_GetAndSet(t *testing.T) {
	state := NewAtomicState[int8](10)
	assert.Equal(t, int8(10), state.Get())

	state.Set(20)
	assert.Equal(t, int8(20), state.Get())
}

func TestAtomicState_CompareAndSwap(t *testing.T) {
	state := NewAtomicState[int8](100)

	// --- Success case ---
	swapped := state.CompareAndSwap(100, -50) // int8 can be negative
	assert.True(t, swapped, "swap should be successful")
	assert.Equal(t, int8(-50), state.Get(), "state should be updated")

	// --- Failure case ---
	swapped = state.CompareAndSwap(100, 120)
	assert.False(t, swapped, "swap should fail")
	assert.Equal(t, int8(-50), state.Get(), "state should remain unchanged")
}

func TestAtomicState_Comparisons(t *testing.T) {
	state := NewAtomicState[int8](50)

	assert.True(t, state.Equal(50))
	assert.False(t, state.Equal(51))

	assert.True(t, state.Gt(49))
	assert.False(t, state.Gt(50))

	assert.True(t, state.Gte(50))
	assert.False(t, state.Gte(51))

	assert.True(t, state.Lt(51))
	assert.False(t, state.Lt(50))

	assert.True(t, state.Lte(50))
	assert.False(t, state.Lte(49))
}

func TestAtomicState_RaceCondition(t *testing.T) {
	state := NewAtomicState[uint8](0)
	var wg sync.WaitGroup
	numGoroutines := 20
	opsPerGoroutine := 100

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				op := rand.Intn(8)
				// Generate random values within the uint8 range (0-255)
				val1 := uint8(rand.Intn(256))
				val2 := uint8(rand.Intn(256))

				switch op {
				case 0:
					state.Set(val1)
				case 1:
					state.Get()
				case 2:
					state.CompareAndSwap(val1, val2)
				case 3:
					state.Equal(val1)
				case 4:
					state.Gt(val1)
				case 5:
					state.Gte(val1)
				case 6:
					state.Lt(val1)
				case 7:
					state.Lte(val1)
				}
			}
		}()
	}
	wg.Wait()

	t.Logf("Race condition test finished with final state: %d", state.Get())
}
