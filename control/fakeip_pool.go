/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"container/list"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	defaultOffset = 2
	// FakeIPTTL is the default TTL for fakeip entries (1 hour)
	FakeIPTTL = 1 * time.Hour
	// FakeIPCleanupInterval is the execution interval for cleanup tasks (10 minutes)
	FakeIPCleanupInterval = 10 * time.Minute
	// DefaultMaxEntries is the default maximum number of entries in the pool
	DefaultMaxEntries = 10000
)

// fakeipEntry represents a fakeip entry
type fakeipEntry struct {
	ip         net.IP
	domain     string
	expireTime time.Time
}

// lruItem represents an item in the LRU cache
type lruItem struct {
	domain string
	entry  *fakeipEntry
}

// fakeipPool is a fakeip pool implementation with LRU cache and automatic cleanup
// Uses the 198.18.0.0/16 address range as the fakeip pool
type fakeipPool struct {
	mu            sync.RWMutex
	domainToElem  map[string]*list.Element // mapping from domain to list element
	ipToDomain    map[string]string        // reverse mapping from IP to domain
	lruList       *list.List               // LRU doubly linked list
	baseIP        net.IP                   // base IP address (198.18.0.0)
	currentOffset uint32                   // current allocation offset
	maxOffset     uint32                   // maximum offset (65536)
	maxEntries    int                      // maximum number of entries
	ttl           time.Duration            // TTL for entries
	stopChan      chan struct{}            // channel to stop cleanup goroutine
	cleanupTicker *time.Ticker             // cleanup ticker
}

var (
	globalFakeipPool     *fakeipPool
	globalFakeipPoolOnce sync.Once
)

// GetGlobalFakeipPool returns the global fakeip pool singleton
func GetGlobalFakeipPool() *fakeipPool {
	globalFakeipPoolOnce.Do(func() {
		globalFakeipPool = newFakeipPool()
		globalFakeipPool.startCleanup()
	})
	return globalFakeipPool
}

// newFakeipPool creates a new fakeip pool
func newFakeipPool() *fakeipPool {
	return &fakeipPool{
		domainToElem:  make(map[string]*list.Element),
		ipToDomain:    make(map[string]string),
		lruList:       list.New(),
		baseIP:        net.ParseIP("198.18.0.0").To4(),
		maxOffset:     65536, // 198.18.0.0/16 can allocate 65536 addresses
		maxEntries:    DefaultMaxEntries,
		ttl:           FakeIPTTL,
		stopChan:      make(chan struct{}),
		currentOffset: defaultOffset,
	}
}

// startCleanup starts the automatic cleanup goroutine
func (p *fakeipPool) startCleanup() {
	p.cleanupTicker = time.NewTicker(FakeIPCleanupInterval)
	go p.cleanupLoop()
}

// cleanupLoop runs the cleanup loop
func (p *fakeipPool) cleanupLoop() {
	for {
		select {
		case <-p.cleanupTicker.C:
			p.cleanup()
		case <-p.stopChan:
			p.cleanupTicker.Stop()
			return
		}
	}
}

// cleanup removes expired entries
func (p *fakeipPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	expiredElems := make([]*list.Element, 0)

	// find all expired entries from the back (oldest)
	for elem := p.lruList.Back(); elem != nil; elem = elem.Prev() {
		item := elem.Value.(*lruItem)
		if now.After(item.entry.expireTime) {
			expiredElems = append(expiredElems, elem)
		}
	}

	// delete expired entries
	for _, elem := range expiredElems {
		item := elem.Value.(*lruItem)
		delete(p.ipToDomain, item.entry.ip.String())
		delete(p.domainToElem, item.domain)
		p.lruList.Remove(elem)
	}
}

// Stop stops the cleanup goroutine
func (p *fakeipPool) Stop() {
	close(p.stopChan)
}

// allocate assigns a fake IP address to a domain
func (p *fakeipPool) allocate(domain string) net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()

	// if the domain already has an IP, update expiration time and move to front (most recently used)
	if elem, exists := p.domainToElem[domain]; exists {
		item := elem.Value.(*lruItem)
		item.entry.expireTime = now.Add(p.ttl)
		p.lruList.MoveToFront(elem)
		return item.entry.ip
	}

	// evict LRU entry if we've reached max capacity
	if p.lruList.Len() >= p.maxEntries {
		p.evictOldest()
	}

	// allocate a new IP
	offset := p.currentOffset
	p.currentOffset++
	if p.currentOffset >= p.maxOffset {
		p.currentOffset = defaultOffset
	}

	// calculate IP address: 198.18.0.0 + offset
	ip := make(net.IP, 4)
	copy(ip, p.baseIP)
	ip[2] = byte(offset >> 8)
	ip[3] = byte(offset & 0xff)

	// create new entry
	entry := &fakeipEntry{
		ip:         ip,
		domain:     domain,
		expireTime: now.Add(p.ttl),
	}

	// if this IP is already occupied, clean up the old mapping first
	ipStr := ip.String()
	if oldDomain, exists := p.ipToDomain[ipStr]; exists {
		if oldElem, ok := p.domainToElem[oldDomain]; ok {
			p.lruList.Remove(oldElem)
			delete(p.domainToElem, oldDomain)
		}
	}

	// create LRU item and add to front (most recently used)
	item := &lruItem{
		domain: domain,
		entry:  entry,
	}
	elem := p.lruList.PushFront(item)

	// save mapping relationships
	p.domainToElem[domain] = elem
	p.ipToDomain[ipStr] = domain

	return ip
}

// evictOldest removes the least recently used entry
// must be called with lock held
func (p *fakeipPool) evictOldest() {
	elem := p.lruList.Back()
	if elem != nil {
		item := elem.Value.(*lruItem)
		delete(p.ipToDomain, item.entry.ip.String())
		delete(p.domainToElem, item.domain)
		p.lruList.Remove(elem)
	}
}

// lookup finds the corresponding domain for a fake IP
func (p *fakeipPool) lookup(ip net.IP) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	domain, exists := p.ipToDomain[ip.String()]
	if !exists {
		return "", false
	}

	// check if expired
	if elem, ok := p.domainToElem[domain]; ok {
		item := elem.Value.(*lruItem)
		if time.Now().After(item.entry.expireTime) {
			return "", false
		}
	}

	if strings.HasSuffix(domain, ".") {
		return domain[:len(domain)-1], true
	}

	return domain, true
}

// GetStats returns pool statistics
func (p *fakeipPool) GetStats() (total int, allocated int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return int(p.maxOffset), p.lruList.Len()
}

type fakeipConn struct {
	net.Conn
	domain string
	dport  uint16
}

func (c fakeipConn) LocalAddr() net.Addr {
	return c
}

func (c fakeipConn) String() string {
	return fmt.Sprintf("%v:%d", c.domain, c.dport)
}

func (c fakeipConn) Network() string {
	return c.Conn.LocalAddr().Network()
}
