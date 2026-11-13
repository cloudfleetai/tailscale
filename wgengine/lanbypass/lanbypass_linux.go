// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package lanbypass

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/envknob"
	"tailscale.com/types/logger"
)

const (
	routeTable    = 54
	rulePref      = 5100 // before Tailscale's own rules, which start at 5200
	nftTableName  = "ts-lanbypass"
	probeInterval = 3 * time.Second
	maxPongAge    = 10 * time.Second
)

// path is how to reach one peer over the shared private network.
type path struct {
	peerLAN  netip.Addr // peer's private address
	localLAN netip.Addr // our address on that network
	gw       netip.Addr // zero if on-link
	link     int
}

// Manager keeps the kernel bypass in sync with the peers that currently answer
// on a private endpoint.
type Manager struct {
	logf   logger.Logf
	src    PeerSource
	ports  []uint16
	ifaces []string // if empty, any interface that is not an overlay link
	cur    map[netip.Addr]path
	cancel context.CancelFunc
	done   chan struct{}
}

// Start begins managing the bypass for the UDP ports in
// TS_LAN_BYPASS_UDP_PORTS (comma separated). It returns nil if that is unset.
// TS_LAN_BYPASS_IFACES optionally limits the bypass to the named interfaces.
func Start(logf logger.Logf, src PeerSource) *Manager {
	var ports []uint16
	for _, s := range strings.Split(envknob.String("TS_LAN_BYPASS_UDP_PORTS"), ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		p, err := strconv.ParseUint(s, 10, 16)
		if err != nil || p == 0 {
			logf("lanbypass: ignoring invalid port %q", s)
			continue
		}
		ports = append(ports, uint16(p))
	}
	if len(ports) == 0 {
		return nil
	}
	var ifaces []string
	for _, s := range strings.Split(envknob.String("TS_LAN_BYPASS_IFACES"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			ifaces = append(ifaces, s)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		logf:   logger.WithPrefix(logf, "lanbypass: "),
		src:    src,
		ports:  ports,
		ifaces: ifaces,
		cur:    map[netip.Addr]path{},
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go m.run(ctx)
	return m
}

// Close removes the bypass and stops the manager.
func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.cancel()
	<-m.done
}

func (m *Manager) run(ctx context.Context) {
	defer close(m.done)
	m.cleanup()
	defer m.cleanup()
	if err := m.addRules(); err != nil {
		m.logf("disabled: %v", err)
		return
	}
	m.logf("enabled for UDP ports %v", m.ports)
	t := time.NewTicker(probeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		paths := make(map[netip.Addr]path)
		var overlay []netip.Addr
		for _, a := range m.src.LANCandidates() {
			switch p, kind := m.pathTo(a); kind {
			case pathDirect:
				paths[a] = p
			case pathOverlay:
				overlay = append(overlay, a)
			}
		}
		m.src.SetOverlayAddrs(overlay)
		peers := m.src.LANPeers(maxPongAge, true, func(a netip.Addr) bool {
			_, ok := paths[a]
			return ok
		})
		want := make(map[netip.Addr]path, len(peers))
		for peer, addrs := range peers {
			want[peer] = paths[addrs[0]]
		}
		if maps.Equal(want, m.cur) {
			continue
		}
		if err := m.apply(want); err != nil {
			m.logf("apply: %v", err)
			m.cleanup()
			if err := m.addRules(); err != nil {
				m.logf("re-adding rules: %v", err)
			}
			continue
		}
	}
}

type pathKind int

const (
	pathNone    pathKind = iota // unroutable, or not an interface the bypass may use
	pathDirect                  // out of an interface that can carry bypassed traffic
	pathOverlay                 // through a tunnel or virtual link
)

// overlayLinkTypes are the link types that an overlay network presents to the
// host. A peer also advertises its address on such a link as an endpoint, and
// using it would send the overlay, or WireGuard itself, through the overlay.
var overlayLinkTypes = map[string]bool{
	"vxlan": true, "geneve": true, "veth": true, "tun": true, "tuntap": true, "ipip": true,
	"gre": true, "gretap": true, "ip6tnl": true, "sit": true, "wireguard": true, "dummy": true,
}

// pathTo reports how the kernel reaches a.
func (m *Manager) pathTo(a netip.Addr) (path, pathKind) {
	routes, err := netlink.RouteGet(net.IP(a.AsSlice()))
	if err != nil || len(routes) == 0 {
		return path{}, pathNone
	}
	r := routes[0]
	link, err := netlink.LinkByIndex(r.LinkIndex)
	if err != nil {
		return path{}, pathNone
	}
	if overlayLinkTypes[link.Type()] {
		return path{}, pathOverlay
	}
	if len(m.ifaces) > 0 && !slices.Contains(m.ifaces, link.Attrs().Name) {
		return path{}, pathNone
	}
	src, ok := netip.AddrFromSlice(r.Src.To4())
	if !ok {
		return path{}, pathNone
	}
	p := path{peerLAN: a, localLAN: src, link: r.LinkIndex}
	if gw, ok := netip.AddrFromSlice(r.Gw.To4()); ok {
		p.gw = gw
	}
	return p, pathDirect
}

func (m *Manager) apply(want map[netip.Addr]path) error {
	// Stale routes go first and new routes last, so a route never exists
	// without its rewrite entry.
	for peer, p := range m.cur {
		if want[peer] != p {
			if err := netlink.RouteDel(route(peer, p)); err != nil && !errors.Is(err, unix.ESRCH) {
				return fmt.Errorf("deleting route to %v: %w", peer, err)
			}
			m.logf("%v: back to the tunnel", peer)
		}
	}
	if err := m.writeNFT(want); err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	for peer, p := range want {
		if m.cur[peer] != p {
			if err := netlink.RouteReplace(route(peer, p)); err != nil {
				return fmt.Errorf("adding route to %v: %w", peer, err)
			}
			m.logf("%v: direct via %v", peer, p.peerLAN)
		}
	}
	m.cur = want
	return nil
}

func route(peer netip.Addr, p path) *netlink.Route {
	r := &netlink.Route{
		Dst:       &net.IPNet{IP: peer.AsSlice(), Mask: net.CIDRMask(32, 32)},
		LinkIndex: p.link,
		Table:     routeTable,
	}
	if p.gw.IsValid() {
		r.Gw = p.gw.AsSlice()
	} else {
		r.Scope = netlink.SCOPE_LINK
	}
	return r
}

func (m *Manager) rules() []*netlink.Rule {
	var rs []*netlink.Rule
	for _, port := range m.ports {
		r := netlink.NewRule()
		r.Family = netlink.FAMILY_V4
		r.Priority = rulePref
		r.Table = routeTable
		r.IPProto = unix.IPPROTO_UDP
		r.Dport = netlink.NewRulePortRange(port, port)
		rs = append(rs, r)
	}
	return rs
}

func (m *Manager) addRules() error {
	for _, r := range m.rules() {
		if err := netlink.RuleAdd(r); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("adding ip rule: %w", err)
		}
	}
	m.checksumFill(true)
	return nil
}

// checksumFill adds or removes a rule that completes pending checksums on
// bypassed packets before their addresses are rewritten.
//
// An overlay that checksums its outer UDP header sends small packets with a
// finished outer checksum and an inner one still to be filled in by the
// device. The kernel's address rewrite then takes the outer checksum for the
// unfinished one and corrupts it. Completing the inner checksum first avoids
// that. Overlays that leave the outer checksum at zero do not need it.
func (m *Manager) checksumFill(add bool) {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		if add {
			m.logf("iptables unavailable (%v): the overlay must not use outer UDP checksums", err)
		}
		return
	}
	for _, port := range m.ports {
		spec := []string{"-p", "udp", "--dport", strconv.Itoa(int(port)), "-d", "100.64.0.0/10", "!", "-o", "tailscale+",
			"-m", "comment", "--comment", "ts-lanbypass", "-j", "CHECKSUM", "--checksum-fill"}
		if !add {
			ipt.DeleteIfExists("mangle", "POSTROUTING", spec...)
		} else if err := ipt.AppendUnique("mangle", "POSTROUTING", spec...); err != nil {
			m.logf("checksum rule: %v: the overlay must not use outer UDP checksums", err)
		}
	}
}

// cleanup removes everything the manager installs, including leftovers from
// a previous process.
func (m *Manager) cleanup() {
	m.checksumFill(false)
	old, _ := netlink.RuleListFiltered(netlink.FAMILY_V4, &netlink.Rule{Priority: rulePref}, netlink.RT_FILTER_PRIORITY)
	for _, r := range old {
		if r.Table == routeTable {
			netlink.RuleDel(&r)
		}
	}
	routes, _ := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: routeTable}, netlink.RT_FILTER_TABLE)
	for _, r := range routes {
		netlink.RouteDel(&r)
	}
	if c, err := nftables.New(); err == nil {
		t := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftTableName})
		c.DelTable(t)
		c.Flush()
	}
	m.cur = map[netip.Addr]path{}
}

// writeNFT atomically replaces the rewrite table. Bypassed packets leave with
// Tailscale addresses, which the private network would not deliver, so their
// source and destination are rewritten to the private addresses on the way out.
func (m *Manager) writeNFT(want map[netip.Addr]path) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftTableName})
	c.DelTable(t)
	if len(want) == 0 {
		return c.Flush()
	}
	t = c.AddTable(t)
	dst := &nftables.Set{Table: t, Name: "dst", IsMap: true, KeyType: nftables.TypeIPAddr, DataType: nftables.TypeIPAddr}
	src := &nftables.Set{Table: t, Name: "src", IsMap: true, KeyType: nftables.TypeIPAddr, DataType: nftables.TypeIPAddr}
	var dstElems, srcElems []nftables.SetElement
	for peer, p := range want {
		dstElems = append(dstElems, nftables.SetElement{Key: peer.AsSlice(), Val: p.peerLAN.AsSlice()})
		srcElems = append(srcElems, nftables.SetElement{Key: peer.AsSlice(), Val: p.localLAN.AsSlice()})
	}
	if err := c.AddSet(dst, dstElems); err != nil {
		return err
	}
	if err := c.AddSet(src, srcElems); err != nil {
		return err
	}
	prio := nftables.ChainPriority(300)
	ch := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    t,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: &prio,
	})
	const (
		ipSrcOff, ipDstOff, ipCsumOff = 12, 16, 10
	)
	rewrite := func(set *nftables.Set, off uint32) []expr.Any {
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: ipDstOff, Len: 4},
			&expr.Lookup{SourceRegister: 1, DestRegister: 1, IsDestRegSet: true, SetName: set.Name, SetID: set.ID},
			&expr.Payload{
				OperationType:  expr.PayloadWrite,
				SourceRegister: 1,
				Base:           expr.PayloadBaseNetworkHeader,
				Offset:         off,
				Len:            4,
				CsumType:       expr.CsumTypeInet,
				CsumOffset:     ipCsumOff,
				CsumFlags:      unix.NFT_PAYLOAD_L4CSUM_PSEUDOHDR,
			},
		}
	}
	for _, port := range m.ports {
		exprs := []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		}
		// The source lookup is keyed on the destination, so it runs first.
		exprs = append(exprs, rewrite(src, ipSrcOff)...)
		exprs = append(exprs, rewrite(dst, ipDstOff)...)
		exprs = append(exprs, &expr.Counter{})
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: exprs})
	}
	return c.Flush()
}
