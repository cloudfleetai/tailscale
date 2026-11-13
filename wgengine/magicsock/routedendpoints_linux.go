// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package magicsock

import (
	"net/netip"

	"github.com/tailscale/netlink"
)

var overlayLinkTypes = map[string]bool{
	"vxlan": true, "geneve": true, "veth": true, "ipip": true, "gre": true,
	"gretap": true, "ip6tnl": true, "sit": true, "wireguard": true, "dummy": true,
}

// overlayLocalAddrs returns the addresses on tunnel and virtual links, such
// as a CNI's host interface. They belong to a network that runs on top of
// this one.
func overlayLocalAddrs() []netip.Addr {
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, l := range links {
		if !overlayLinkTypes[l.Type()] {
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
