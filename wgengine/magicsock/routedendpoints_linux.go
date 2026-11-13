// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package magicsock

import (
	"net/netip"

	"github.com/tailscale/netlink"
	"tailscale.com/net/netmon"
)

var overlayLinkTypes = map[string]bool{
	"vxlan": true, "geneve": true, "veth": true, "ipip": true, "gre": true,
	"gretap": true, "ip6tnl": true, "sit": true, "wireguard": true, "dummy": true,
}

// overlayLocalAddrs returns the addresses on tunnel and virtual links, such
// as a CNI's host interface. The default route's interface is never one of
// them: in a container it is a veth and the only way in.
func overlayLocalAddrs() []netip.Addr {
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}
	uplink, _ := netmon.DefaultRouteInterface()
	var out []netip.Addr
	for _, l := range links {
		if !isOverlayLink(l.Type(), l.Attrs().Name, uplink) {
			continue
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ip, ok := netip.AddrFromSlice(a.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

func isOverlayLink(kind, name, uplink string) bool {
	return overlayLinkTypes[kind] && name != uplink
}
