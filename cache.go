package main

import "sync"

// boundedCache keeps the last values stored, dropping the oldest one when
// full. It is safe for concurrent use.
type boundedCache[V any] struct {
	size int

	mu     sync.Mutex
	values map[string]V
	order  []string
}

func newBoundedCache[V any](size int) *boundedCache[V] {
	return &boundedCache[V]{size: size, values: make(map[string]V)}
}

func (c *boundedCache[V]) get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, ok := c.values[key]
	return value, ok
}

func (c *boundedCache[V]) put(key string, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.values[key]; !ok {
		if len(c.order) >= c.size {
			delete(c.values, c.order[0])
			c.order = c.order[1:]
		}
		c.order = append(c.order, key)
	}
	c.values[key] = value
}

func (c *boundedCache[V]) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values, c.order = make(map[string]V), nil
}
