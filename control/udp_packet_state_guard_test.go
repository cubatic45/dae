/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Exercise the real map deletion path: a stale endpoint must not remove the
// current packet's attribution before its replacement acquires ownership.
// Final endpoint release must still delete both directions.
func TestUdpPacketConnStateGuardEndpointReplacement(t *testing.T) {
	for _, useManager := range []bool{false, true} {
		for _, ipv6 := range []bool{false, true} {
			for _, changeServer := range []bool{false, true} {
				ownerName, family, destination := "core", "ipv4", "same"
				if useManager {
					ownerName = "manager"
				}
				if ipv6 {
					family = "ipv6"
				}
				if changeServer {
					destination = "changed"
				}
				t.Run(ownerName+"/"+family+"/"+destination, func(t *testing.T) {
					connMap := newJanitorTestMap(t, "conn_state_map")
					bpf := &bpfObjects{bpfMaps: bpfMaps{ConnStateMap: connMap}}
					core := &controlPlaneCore{}
					core.bpf.Store(bpf)
					core.udpConnStateTracker.Store(newUdpConnStateTracker())
					cp := &ControlPlane{core: core}
					var owner udpConnStateOwner = core
					if useManager {
						manager := NewSessionManager(context.Background())
						manager.udpBPF.Store(bpf)
						cp.sessionManager = manager
						owner = manager
					}
					src := netip.MustParseAddrPort("192.0.2.10:3074")
					oldDst := netip.MustParseAddrPort("198.51.100.10:30004")
					newDst := netip.MustParseAddrPort("198.51.100.11:30007")
					if ipv6 {
						src = netip.MustParseAddrPort("[2001:db8::10]:3074")
						oldDst = netip.MustParseAddrPort("[2001:db8::20]:30004")
						newDst = netip.MustParseAddrPort("[2001:db8::21]:30007")
					}
					if !changeServer {
						newDst = oldDst
					}
					old := &UdpEndpoint{udpConnStateOwner: owner}
					old.TrackUdpConnStateTuplePair(src, oldDst)
					keys := [2]bpfTuplesKey{
						bpfTuplesKeyFromAddrPorts(src, newDst, unix.IPPROTO_UDP),
						bpfTuplesKeyFromAddrPorts(newDst, src, unix.IPPROTO_UDP),
					}
					state := bpfConnState{LastSeenNs: 123}
					state.Meta.Data.HasRouting = 1
					state.Meta.Data.Outbound = 2
					for _, key := range keys {
						if err := connMap.Update(&key, &state, ebpf.UpdateAny); err != nil {
							t.Fatal(err)
						}
					}
					assertPresent := func() {
						t.Helper()
						for _, key := range keys {
							var got bpfConnState
							if err := connMap.Lookup(&key, &got); err != nil {
								t.Fatalf("packet conn-state deleted during replacement: %v", err)
							}
							if got != state {
								t.Fatalf("routing attribution changed: got %+v, want %+v", got, state)
							}
						}
					}
					guard := cp.pinUdpConnStateForPacket(src, newDst)
					if guard.owner != owner {
						t.Fatal("packet and endpoint conn-state owners differ")
					}
					old.TrackUdpConnStateTuplePair(src, newDst)
					// Retirement can run on the receiver goroutine as well as WriteTo.
					retired := make(chan struct{})
					go func() {
						old.releaseTrackedUdpConnState()
						close(retired)
					}()
					<-retired
					assertPresent()
					replacement := &UdpEndpoint{udpConnStateOwner: owner}
					replacement.TrackUdpConnStateTuplePair(src, newDst)
					guard.release(nil)
					assertPresent()
					replacement.releaseTrackedUdpConnState()
					for _, key := range keys {
						var got bpfConnState
						if err := connMap.Lookup(&key, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
							t.Fatalf("last endpoint release did not delete state: %v", err)
						}
					}
					// A failed dial leaves only the packet reference. Its deferred
					// release must not leave a permanent pin or kernel entry.
					for _, key := range keys {
						if err := connMap.Update(&key, &state, ebpf.UpdateAny); err != nil {
							t.Fatal(err)
						}
					}
					cp.pinUdpConnStateForPacket(src, newDst).release(nil)
					for _, key := range keys {
						var got bpfConnState
						if err := connMap.Lookup(&key, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
							t.Fatalf("packet-only state leaked: %v", err)
						}
					}
				})
			}
		}
	}
}

func TestUdpPacketConnStateGuardWithoutOwner(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:3074")
	dst := netip.MustParseAddrPort("198.51.100.10:30004")
	for _, cp := range []*ControlPlane{nil, {}} {
		guard := cp.pinUdpConnStateForPacket(src, dst)
		if guard != nil {
			t.Fatal("unexpected owner for empty control plane")
		}
		guard.release(nil)
	}
	cp := &ControlPlane{sessionManager: NewSessionManager(context.Background())}
	guard := cp.pinUdpConnStateForPacket(netip.AddrPort{}, dst)
	if guard != nil {
		t.Fatal("invalid address acquired a pin")
	}
	guard.release(nil)
}

// Keep an endpoint reference alive so this measures steady-state packet
// bookkeeping, without a kernel map deletion or a new flow on each iteration.
func BenchmarkUdpPacketConnStateGuard(b *testing.B) {
	manager := NewSessionManager(context.Background())
	cp := &ControlPlane{sessionManager: manager}
	src := netip.MustParseAddrPort("192.0.2.10:3074")
	dst := netip.MustParseAddrPort("198.51.100.10:30004")
	endpoint := &UdpEndpoint{udpConnStateOwner: manager}
	endpoint.TrackUdpConnStateTuplePair(src, dst)
	b.Cleanup(endpoint.releaseTrackedUdpConnState)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		guard := cp.pinUdpConnStateForPacket(src, dst)
		guard.release(nil)
	}
}
