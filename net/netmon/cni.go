// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"slices"
	"strings"
)

// cniInterfacePrefixes are the name prefixes of the host interfaces Cilium
// creates: cilium_host, cilium_net, cilium_vxlan, cilium_geneve and one lxc
// interface per pod.
var cniInterfacePrefixes = []string{"cilium_", "lxc"}

// isCNIInterface reports whether name is a host interface of a Kubernetes
// CNI. Its addresses are in the pod network, which may run over Tailscale.
func isCNIInterface(name string) bool {
	return slices.ContainsFunc(cniInterfacePrefixes, func(p string) bool {
		return strings.HasPrefix(name, p)
	})
}
