/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
	"github.com/safchain/ethtool"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// coreFlip should be 0 or 1
var coreFlip = 0

type controlPlaneCore struct {
	mu sync.Mutex

	log             *logrus.Logger
	deferFuncs      []func() error
	bpf             *bpfObjects
	outboundId2Name map[uint8]string

	kernelVersion *internal.Version

	flip       int
	isReload   bool
	bpfEjected bool

	closed context.Context
	close  context.CancelFunc
	ifmgr  *component.InterfaceManager
}

func newControlPlaneCore(log *logrus.Logger,
	bpf *bpfObjects,
	outboundId2Name map[uint8]string,
	kernelVersion *internal.Version,
	isReload bool,
) *controlPlaneCore {
	if isReload {
		coreFlip = coreFlip&1 ^ 1
	}
	var deferFuncs []func() error
	if !isReload {
		deferFuncs = append(deferFuncs, bpf.Close)
	}
	closed, toClose := context.WithCancel(context.Background())
	ifmgr := component.NewInterfaceManager(log)
	deferFuncs = append(deferFuncs, ifmgr.Close)
	return &controlPlaneCore{
		log:             log,
		deferFuncs:      deferFuncs,
		bpf:             bpf,
		outboundId2Name: outboundId2Name,
		kernelVersion:   kernelVersion,
		flip:            coreFlip,
		isReload:        isReload,
		bpfEjected:      false,
		ifmgr:           ifmgr,
		closed:          closed,
		close:           toClose,
	}
}

func (c *controlPlaneCore) Flip() {
	coreFlip = coreFlip&1 ^ 1
}
func (c *controlPlaneCore) Close() (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	// Invoke defer funcs in reverse order.
	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		if e := c.deferFuncs[i](); e != nil {
			// Combine errors.
			if err != nil {
				err = fmt.Errorf("%w; %v", err, e)
			} else {
				err = e
			}
		}
	}
	c.close()
	return err
}

func getIfParamsFromLink(link netlink.Link) (ifParams bpfIfParams, err error) {
	// Get link offload features.
	et, err := ethtool.NewEthtool()
	if err != nil {
		return bpfIfParams{}, err
	}
	defer et.Close()
	features, err := et.Features(link.Attrs().Name)
	if err != nil {
		return bpfIfParams{}, err
	}
	if features["tx-checksum-ip-generic"] {
		ifParams.TxL4CksmIp4Offload = true
		ifParams.TxL4CksmIp6Offload = true
	}
	if features["tx-checksum-ipv4"] {
		ifParams.TxL4CksmIp4Offload = true
	}
	if features["tx-checksum-ipv6"] {
		ifParams.TxL4CksmIp6Offload = true
	}
	if features["rx-checksum"] {
		ifParams.RxCksmOffload = true
	}
	switch {
	case regexp.MustCompile(`^docker\d+$`).MatchString(link.Attrs().Name):
		ifParams.UseNonstandardOffloadAlgorithm = true
	default:
	}
	return ifParams, nil
}

func (c *controlPlaneCore) linkHdrLen(ifname string) (uint32, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return 0, err
	}
	var linkHdrLen uint32
	switch link.Attrs().EncapType {
	case "none", "ipip", "ppp", "tun":
		linkHdrLen = consts.LinkHdrLen_None
	case "ether":
		linkHdrLen = consts.LinkHdrLen_Ethernet
	default:
		c.log.Warnf("Maybe unsupported link type %v, using default link header length", link.Attrs().EncapType)
		linkHdrLen = consts.LinkHdrLen_Ethernet
	}
	return linkHdrLen, nil
}

func (c *controlPlaneCore) addQdisc(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("cannot add clsact qdisc: %w", err)
	}
	return nil
}

func (c *controlPlaneCore) delQdisc(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscDel(qdisc); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("cannot add clsact qdisc: %w", err)
		}
	}
	return nil
}

// bindLan automatically configures kernel parameters and bind to lan interface `ifname`.
// bindLan supports lazy-bind if interface `ifname` is not found.
// bindLan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindLan(ifname string, autoConfigKernelParameter bool) {
	initlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		if autoConfigKernelParameter {
			SetSendRedirects(link.Attrs().Name, "0")
			SetForwarding(link.Attrs().Name, "1")
		}
		if err := c._bindLan(link.Attrs().Name); err != nil {
			c.log.Errorf("bindLan: %v", err)
		}
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("New link creation of '%v' is detected. Bind LAN program to it.", link.Attrs().Name)
		if err := c.addQdisc(link.Attrs().Name); err != nil {
			c.log.Errorf("addQdisc: %v", err)
			return
		}
		initlinkCallback(link)
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("Link deletion of '%v' is detected. Bind LAN program to it once it is re-created.", link.Attrs().Name)
	}
	c.ifmgr.RegisterWithPattern(ifname, initlinkCallback, newlinkCallback, dellinkCallback)
}

func (c *controlPlaneCore) _bindLan(ifname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	c.log.Infof("Bind to LAN: %v", ifname)

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if err = CheckIpforward(ifname); err != nil {
		return err
	}
	if err = CheckSendRedirects(ifname); err != nil {
		return err
	}
	_ = c.addQdisc(ifname)
	linkHdrLen, err := c.linkHdrLen(ifname)
	if err != nil {
		return err
	}
	/// Insert an elem into IfindexParamsMap.
	ifParams, err := getIfParamsFromLink(link)
	if err != nil {
		return err
	}
	if err = ifParams.CheckVersionRequirement(c.kernelVersion); err != nil {
		return err
	}

	// Insert filters.
	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b100+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			// Priority should be behind of WAN's
			Priority: 2,
		},
		Name:         consts.AppName + "_lan_ingress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterIngress.Fd = c.bpf.bpfPrograms.TproxyLanIngressL2.FD()
		filterIngress.Name = filterIngress.Name + "_l2"
	} else {
		filterIngress.Fd = c.bpf.bpfPrograms.TproxyLanIngressL3.FD()
		filterIngress.Name = filterIngress.Name + "_l3"
	}
	// Remove and add.
	_ = netlink.FilterDel(filterIngress)
	if !c.isReload {
		// Clean up thoroughly.
		filterIngressFlipped := deepcopy.Copy(filterIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterIngressFlipped)
	}
	if err := netlink.FilterAdd(filterIngress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterIngress); err != nil {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterIngress.Name, err)
		}
		return nil
	})

	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			// Priority should be front of WAN's
			Priority: 1,
		},
		Name:         consts.AppName + "_lan_egress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterEgress.Fd = c.bpf.bpfPrograms.TproxyLanEgressL2.FD()
		filterEgress.Name = filterEgress.Name + "_l2"
	} else {
		filterEgress.Fd = c.bpf.bpfPrograms.TproxyLanEgressL3.FD()
		filterEgress.Name = filterEgress.Name + "_l3"
	}
	// Remove and add.
	_ = netlink.FilterDel(filterEgress)
	if !c.isReload {
		// Clean up thoroughly.
		filterEgressFlipped := deepcopy.Copy(filterEgress).(*netlink.BpfFilter)
		filterEgressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterEgressFlipped)
	}
	if err := netlink.FilterAdd(filterEgress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter egress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterEgress); err != nil {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterEgress.Name, err)
		}
		return nil
	})

	return nil
}

func (c *controlPlaneCore) setupSkPidMonitor() error {
	/// Set-up SrcPidMapper.
	/// Attach programs to support pname routing.
	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		return err
	}
	// Bind cg programs
	type cgProg struct {
		Name   string
		Prog   *ebpf.Program
		Attach ebpf.AttachType
	}
	cgProgs := []cgProg{
		{Prog: c.bpf.TproxyWanCgSockCreate, Attach: ebpf.AttachCGroupInetSockCreate},
		{Prog: c.bpf.TproxyWanCgSockRelease, Attach: ebpf.AttachCgroupInetSockRelease},
		{Prog: c.bpf.TproxyWanCgConnect4, Attach: ebpf.AttachCGroupInet4Connect},
		{Prog: c.bpf.TproxyWanCgConnect6, Attach: ebpf.AttachCGroupInet6Connect},
		{Prog: c.bpf.TproxyWanCgSendmsg4, Attach: ebpf.AttachCGroupUDP4Sendmsg},
		{Prog: c.bpf.TproxyWanCgSendmsg6, Attach: ebpf.AttachCGroupUDP6Sendmsg},
	}
	for _, prog := range cgProgs {
		attached, err := ciliumLink.AttachCgroup(ciliumLink.CgroupOptions{
			Path:    cgroupPath,
			Attach:  prog.Attach,
			Program: prog.Prog,
		})
		if err != nil {
			return fmt.Errorf("AttachCgroup: %v: %w", prog.Prog.String(), err)
		}
		c.deferFuncs = append(c.deferFuncs, func() error {
			if err := attached.Close(); err != nil {
				return fmt.Errorf("inet6Bind.Close(): %w", err)
			}
			return nil
		})
	}
	return nil
}

func (c *controlPlaneCore) setupLocalTcpFastRedirect() (err error) {
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		return
	}
	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: c.bpf.LocalTcpSockops, // todo@gray: rename
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		return fmt.Errorf("AttachCgroupSockOps: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, cg.Close)

	if err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  c.bpf.FastSock.FD(),
		Program: c.bpf.SkMsgFastRedirect,
		Attach:  ebpf.AttachSkMsgVerdict,
	}); err != nil {
		return fmt.Errorf("AttachSkMsgVerdict: %w", err)
	}
	return nil

}

// bindWan supports lazy-bind if interface `ifname` is not found.
// bindWan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindWan(ifname string, autoConfigKernelParameter bool) {
	initlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		if err := c._bindWan(link.Attrs().Name); err != nil {
			c.log.Errorf("bindWan: %v", err)
		}
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("New link creation of '%v' is detected. Bind WAN program to it.", link.Attrs().Name)
		if err := c.addQdisc(link.Attrs().Name); err != nil {
			c.log.Errorf("addQdisc: %v", err)
			return
		}
		initlinkCallback(link)
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("Link deletion of '%v' is detected. Bind WAN program to it once it is re-created.", link.Attrs().Name)
	}
	c.ifmgr.RegisterWithPattern(ifname, initlinkCallback, newlinkCallback, dellinkCallback)
}

func (c *controlPlaneCore) _bindWan(ifname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	c.log.Infof("Bind to WAN: %v", ifname)
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if link.Attrs().Index == consts.LoopbackIfIndex {
		return fmt.Errorf("cannot bind to loopback interface")
	}
	_ = c.addQdisc(ifname)
	linkHdrLen, err := c.linkHdrLen(ifname)
	if err != nil {
		return err
	}

	/// Insert an elem into IfindexParamsMap.
	ifParams, err := getIfParamsFromLink(link)
	if err != nil {
		return err
	}
	if err = ifParams.CheckVersionRequirement(c.kernelVersion); err != nil {
		return err
	}

	/// Set-up WAN ingress/egress TC programs.
	// Insert TC filters
	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b100+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  2,
		},
		Name:         consts.AppName + "_wan_egress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterEgress.Fd = c.bpf.bpfPrograms.TproxyWanEgressL2.FD()
		filterEgress.Name = filterEgress.Name + "_l2"
	} else {
		filterEgress.Fd = c.bpf.bpfPrograms.TproxyWanEgressL3.FD()
		filterEgress.Name = filterEgress.Name + "_l3"
	}
	_ = netlink.FilterDel(filterEgress)
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly.
		filterEgressFlipped := deepcopy.Copy(filterEgress).(*netlink.BpfFilter)
		filterEgressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterEgressFlipped)
	}
	if err := netlink.FilterAdd(filterEgress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter egress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterEgress); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterEgress.Name, err)
		}
		return nil
	})

	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Name:         consts.AppName + "_wan_ingress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterIngress.Fd = c.bpf.bpfPrograms.TproxyWanIngressL2.FD()
		filterIngress.Name = filterIngress.Name + "_l2"
	} else {
		filterIngress.Fd = c.bpf.bpfPrograms.TproxyWanIngressL3.FD()
		filterIngress.Name = filterIngress.Name + "_l3"
	}
	_ = netlink.FilterDel(filterIngress)
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly.
		filterIngressFlipped := deepcopy.Copy(filterIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterIngressFlipped)
	}
	if err := netlink.FilterAdd(filterIngress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterIngress); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterIngress.Name, err)
		}
		return nil
	})

	return nil
}

func (c *controlPlaneCore) bindDaens() (err error) {
	daens := GetDaeNetns()

	// tproxy_dae0peer_ingress@eth0 at dae netns
	daens.With(func() error {
		return c.addQdisc(daens.Dae0Peer().Attrs().Name)
	})
	filterDae0peerIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: daens.Dae0Peer().Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2022, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.bpfPrograms.TproxyDae0peerIngress.FD(),
		Name:         consts.AppName + "_dae0peer_ingress",
		DirectAction: true,
	}
	daens.With(func() error {
		return netlink.FilterDel(filterDae0peerIngress)
	})
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly.
		filterIngressFlipped := deepcopy.Copy(filterDae0peerIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		daens.With(func() error {
			return netlink.FilterDel(filterDae0peerIngress)
		})
	}
	if err = daens.With(func() error {
		return netlink.FilterAdd(filterDae0peerIngress)
	}); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		daens.With(func() error {
			return netlink.FilterDel(filterDae0peerIngress)
		})
		return nil
	})

	// tproxy_dae0_ingress@dae0 at host netns
	c.addQdisc(daens.Dae0().Attrs().Name)
	filterDae0Ingress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: daens.Dae0().Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2022, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.bpfPrograms.TproxyDae0Ingress.FD(),
		Name:         consts.AppName + "_dae0_ingress",
		DirectAction: true,
	}
	_ = netlink.FilterDel(filterDae0Ingress)
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly.
		filterEgressFlipped := deepcopy.Copy(filterDae0Ingress).(*netlink.BpfFilter)
		filterEgressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterEgressFlipped)
	}
	if err := netlink.FilterAdd(filterDae0Ingress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter egress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterDae0Ingress); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("FilterDel(%v:%v): %w", daens.Dae0().Attrs().Name, filterDae0Ingress.Name, err)
		}
		return nil
	})
	return
}

// BatchUpdateDomainRouting update bpf map domain_routing. Since one IP may have multiple domains, this function should
// be invoked every A/AAAA-record lookup.
func (c *controlPlaneCore) BatchUpdateDomainRouting(cache *DnsCache) error {
	// Parse ips from DNS resp answers.
	var ips []netip.Addr
	for _, ans := range cache.Answer {
		var (
			ip netip.Addr
			ok bool
		)
		switch body := ans.(type) {
		case *dnsmessage.A:
			ip, ok = netip.AddrFromSlice(body.A)
		case *dnsmessage.AAAA:
			ip, ok = netip.AddrFromSlice(body.AAAA)
		}
		if !ok || ip.IsUnspecified() {
			continue
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil
	}

	// Update bpf map.
	// Construct keys and vals, and BpfMapBatchUpdate.
	var keys [][4]uint32
	var vals []bpfDomainRouting
	for _, ip := range ips {
		ip6 := ip.As16()
		keys = append(keys, common.Ipv6ByteSliceToUint32Array(ip6[:]))
		r := bpfDomainRouting{}
		if len(cache.DomainBitmap) != len(r.Bitmap) {
			return fmt.Errorf("domain bitmap length not sync with kern program")
		}
		copy(r.Bitmap[:], cache.DomainBitmap)
		vals = append(vals, r)
	}
	if _, err := BpfMapBatchUpdate(c.bpf.DomainRoutingMap, keys, vals, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return err
	}
	return nil
}

// BatchRemoveDomainRouting remove bpf map domain_routing.
func (c *controlPlaneCore) BatchRemoveDomainRouting(cache *DnsCache) error {
	// Parse ips from DNS resp answers.
	var ips []netip.Addr
	for _, ans := range cache.Answer {
		var (
			ip netip.Addr
			ok bool
		)
		switch body := ans.(type) {
		case *dnsmessage.A:
			ip, ok = netip.AddrFromSlice(body.A)
		case *dnsmessage.AAAA:
			ip, ok = netip.AddrFromSlice(body.AAAA)
		}
		if !ok || ip.IsUnspecified() {
			continue
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil
	}

	// Update bpf map.
	// Construct keys and vals, and BpfMapBatchUpdate.
	var keys [][4]uint32
	for _, ip := range ips {
		ip6 := ip.As16()
		keys = append(keys, common.Ipv6ByteSliceToUint32Array(ip6[:]))
	}
	if _, err := BpfMapBatchDelete(c.bpf.DomainRoutingMap, keys); err != nil {
		return err
	}
	return nil
}

// EjectBpf will resect bpf from destroying life-cycle of control plane core.
func (c *controlPlaneCore) EjectBpf() *bpfObjects {
	if !c.bpfEjected && !c.isReload {
		c.deferFuncs = c.deferFuncs[1:]
	}
	c.bpfEjected = true
	return c.bpf
}

// InjectBpf will inject bpf back.
func (c *controlPlaneCore) InjectBpf(bpf *bpfObjects) {
	if c.bpfEjected {
		c.bpfEjected = false
		c.deferFuncs = append([]func() error{bpf.Close}, c.deferFuncs...)
	}
	return
}
