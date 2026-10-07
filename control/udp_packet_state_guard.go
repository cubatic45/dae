/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// udpPacketConnStateGuard bridges endpoint replacement with a packet-owned
// reference. Its owner must match the owner used when creating endpoints.
type udpPacketConnStateGuard struct {
	owner udpConnStateOwner
	keys  [2]bpfTuplesKey
}

func (c *ControlPlane) pinUdpConnStateForPacket(src, dst netip.AddrPort) *udpPacketConnStateGuard {
	if c == nil || !src.IsValid() || !dst.IsValid() {
		return nil
	}
	var owner udpConnStateOwner
	if manager, _ := c.controlPlaneSessionManager(); manager != nil {
		owner = manager
	} else if c.core != nil {
		owner = c.core
	}
	if owner == nil {
		return nil
	}
	guard := &udpPacketConnStateGuard{
		owner: owner,
		keys: [2]bpfTuplesKey{
			bpfTuplesKeyFromAddrPorts(src, dst, unix.IPPROTO_UDP),
			bpfTuplesKeyFromAddrPorts(dst, src, unix.IPPROTO_UDP),
		},
	}
	owner.RetainUdpConnStateTuples(guard.keys[:])
	return guard
}

func (guard *udpPacketConnStateGuard) release(log *logrus.Logger) {
	if guard == nil || guard.owner == nil {
		return
	}
	if err := guard.owner.ReleaseUdpConnStateTuples(guard.keys[:]); err != nil && log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
		log.WithError(err).Debug("Failed to release packet-owned UDP conn-state")
	}
}
