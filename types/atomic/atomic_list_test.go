package atomic

import (
	"math/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAtomicList_ConcurrentInsert(t *testing.T) {
	list := NewAtomicList[int]()
	var wg sync.WaitGroup
	numGoroutines := 100
	numInsertsPerGoroutine := 10

	wg.Add(numGoroutines)
	for range numGoroutines {
		go func() {
			defer wg.Done()
			for j := 0; j < numInsertsPerGoroutine; j++ {
				list.Insert(j)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, numGoroutines*numInsertsPerGoroutine, list.Len())
}

func TestAtomicList_ConcurrentReadWrite(t *testing.T) {
	list := NewAtomicList[int]()
	var wg sync.WaitGroup
	numGoroutines := 50

	// Initial data setup
	for i := range 100 {
		list.Insert(i)
	}

	wg.Add(numGoroutines * 3)

	// Read goroutines
	for range numGoroutines {
		go func() {
			defer wg.Done()
			_, _ = list.Get(10) // Index 10 will always exist
			_ = list.Len()
			_ = list.Contains(20)
		}()
	}

	// Write goroutines
	for i := range numGoroutines {
		go func(val int) {
			defer wg.Done()
			list.Insert(100 + val)
		}(i)
	}

	// Delete goroutines
	for i := range numGoroutines {
		go func(val int) {
			defer wg.Done()
			// For this test, we don't need to check the error on Remove.
			list.Remove(val)
		}(i)
	}
	wg.Wait()

	// 100 (initial) + 50 (writes) - 50 (deletes) = 100
	assert.Equal(t, 100, list.Len())
}

func TestAtomicList_IteratorConcurrent(t *testing.T) {
	list := NewAtomicList[int]()
	for i := 0; i < 1000; i++ {
		list.Insert(i)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine using the iterator
	go func() {
		defer wg.Done()
		count := 0
		for range list.Iterator() {
			count++
		}
	}()

	// Goroutine that modifies the original list
	go func() {
		defer wg.Done()
		list.Remove(500)
	}()
	wg.Wait()

	assert.Equal(t, 999, list.Len())
}

func TestAtomicList_RaceCondition(t *testing.T) {
	list := NewAtomicList[int]()
	var wg sync.WaitGroup
	numGoroutines := 20
	numOpsPerGoroutine := 100

	// Initial data
	for i := range 100 {
		list.Insert(i)
	}

	wg.Add(numGoroutines)
	for range numGoroutines {
		go func() {
			defer wg.Done()
			for j := 0; j < numOpsPerGoroutine; j++ {
				// Generate a random number between 0 and 7 to perform a random operation.
				op := rand.Intn(8)
				switch op {
				case 0: // Insert
					list.Insert(rand.Intn(1000))
				case 1: // Remove
					list.Remove(rand.Intn(1000))
				case 2: // Get
					l := list.Len()
					if l > 0 {
						list.Get(rand.Intn(l))
					}
				case 3: // Contains
					list.Contains(rand.Intn(1000))
				case 4: // Len
					list.Len()
				case 5: // First
					list.First()
				case 6: // Last
					list.Last()
				case 7: // Iterator
					for range list.Iterator() {
						// Just perform the iteration.
					}
				}
			}
		}()
	}

	wg.Wait()
	t.Logf("Race condition test finished with final list length: %d", list.Len())
}
