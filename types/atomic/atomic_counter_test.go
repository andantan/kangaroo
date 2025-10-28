package atomic

import (
	"github.com/stretchr/testify/assert"
	"math/rand"
	"sync"
	"testing"
)

func TestAtomicCounter_GetAndSet(t *testing.T) {
	counter := NewAtomicCounter[int](100)
	assert.Equal(t, 100, counter.Get())

	counter.Set(200)
	assert.Equal(t, 200, counter.Get())
}

func TestAtomicCounter_AddAndIncrement(t *testing.T) {
	counter := NewAtomicCounter[int64](10)

	newValue := counter.Add(5)
	assert.Equal(t, int64(15), newValue)
	assert.Equal(t, int64(15), counter.Get())

	newValue = counter.Increment()
	assert.Equal(t, int64(16), newValue)
	assert.Equal(t, int64(16), counter.Get())
}

func TestAtomicCounter_SubAndDecrement(t *testing.T) {
	// --- Signed Integer Test ---
	signedCounter := NewAtomicCounter[int](10)
	signedCounter.Sub(4)
	assert.Equal(t, 6, signedCounter.Get())
	signedCounter.Decrement()
	assert.Equal(t, 5, signedCounter.Get())

	// --- Unsigned Integer Underflow Test ---
	unsignedCounter := NewAtomicCounter[uint](5)
	unsignedCounter.Decrement() // 4
	unsignedCounter.Decrement() // 3
	assert.Equal(t, uint(3), unsignedCounter.Get())

	// Subtracting more than the current value should result in 0
	unsignedCounter.Sub(100)
	assert.Equal(t, uint(0), unsignedCounter.Get())

	// Decrementing from 0 should remain 0
	unsignedCounter.Decrement()
	assert.Equal(t, uint(0), unsignedCounter.Get())
}

func TestAtomicCounter_CompareAndSwap(t *testing.T) {
	counter := NewAtomicCounter[int](50)

	// Success case
	swapped := counter.CompareAndSwap(50, 60)
	assert.True(t, swapped)
	assert.Equal(t, 60, counter.Get())

	// Failure case
	swapped = counter.CompareAndSwap(50, 70)
	assert.False(t, swapped)
	assert.Equal(t, 60, counter.Get())
}

func TestAtomicCounter_Comparisons(t *testing.T) {
	counter := NewAtomicCounter[int](100)

	assert.True(t, counter.Equal(100))
	assert.False(t, counter.Equal(99))

	assert.True(t, counter.Gt(99))
	assert.False(t, counter.Gt(100))

	assert.True(t, counter.Gte(100))
	assert.False(t, counter.Gte(101))

	assert.True(t, counter.Lt(101))
	assert.False(t, counter.Lt(100))

	assert.True(t, counter.Lte(100))
	assert.False(t, counter.Lte(99))
}

func TestAtomicCounter_RaceCondition(t *testing.T) {
	counter := NewAtomicCounter[int](0)
	var wg sync.WaitGroup
	numGoroutines := 50
	opsPerGoroutine := 100

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				op := rand.Intn(12)

				switch op {
				case 0:
					counter.Add(1)
				case 1:
					counter.Sub(1)
				case 2:
					counter.Increment()
				case 3:
					counter.Decrement()
				case 4:
					counter.Get()
				case 5:
					counter.CompareAndSwap(rand.Intn(10), rand.Intn(10))
				case 6:
					counter.Set(rand.Intn(100))
				case 7:
					counter.Equal(rand.Intn(100))
				case 8:
					counter.Gt(rand.Intn(100))
				case 9:
					counter.Gte(rand.Intn(100))
				case 10:
					counter.Lt(rand.Intn(100))
				case 11:
					counter.Lte(rand.Intn(100))
				}
			}
		}()
	}
	wg.Wait()

	t.Logf("Race condition test finished with final counter value: %d", counter.Get())
}
