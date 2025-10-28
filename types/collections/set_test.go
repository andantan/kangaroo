package collections

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSet_AddAndLen(t *testing.T) {
	s := NewSet[int]()
	assert.Equal(t, 0, s.Len())

	s.Add(10)
	s.Add(20)
	assert.Equal(t, 2, s.Len())

	s.Add(10)
	assert.Equal(t, 2, s.Len(), "adding a duplicate element should not change the length")
}

func TestSet_Remove(t *testing.T) {
	s := NewSet[string]()
	s.Add("cat")
	s.Add("dog")
	s.Add("lion")

	s.Remove("dog")
	assert.Equal(t, 2, s.Len())
	assert.False(t, s.Contains("dog"))

	s.Remove("tiger")
	assert.Equal(t, 2, s.Len())
}

func TestSet_Clear(t *testing.T) {
	s := NewSet[int]()
	s.Add(100)
	s.Add(200)
	s.Clear()

	assert.Equal(t, 0, s.Len())
	assert.Equal(t, 0, len(s.data))
}

func TestSet_Contains(t *testing.T) {
	s := NewSet[rune]()
	s.Add('a')
	s.Add('b')

	assert.True(t, s.Contains('a'))
	assert.True(t, s.Contains('b'))
	assert.False(t, s.Contains('c'))
}

func TestSet_Values(t *testing.T) {
	s := NewSet[int]()
	s.Add(1)
	s.Add(2)

	values := s.Values()
	assert.ElementsMatch(t, []int{1, 2}, values)

	values[0] = 99
	assert.True(t, s.Contains(1), "modifying the returned slice should not affect the original set")
	assert.False(t, s.Contains(99))
}

func TestSet_Iterator(t *testing.T) {
	s := NewSet[rune]()
	s.Add('x')
	s.Add('y')
	s.Add('z')

	var results []rune
	for val := range s.Iterator() {
		results = append(results, val)
	}
	assert.ElementsMatch(t, []rune{'x', 'y', 'z'}, results)

	// Iterator가 중간에 멈추는지 테스트
	var count int
	for range s.Iterator() {
		count++
		if count == 2 {
			break
		}
	}
	assert.Equal(t, 2, count)
}
