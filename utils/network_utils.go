package utils

import "net"

type IPSlash net.IPNet

func NetworkIpv4Addr(n net.IPNet) net.IP {
	network := net.IPv4zero.To4()
	ip4 := n.IP.To4()
	var mask net.IPMask
	if len(n.Mask) == 16 {
		mask = n.Mask[12:]
	} else {
		mask = n.Mask
	}
	for i := 0; i < len(ip4); i++ {
		network[i] = ip4[i] & mask[i]
	}
	return network.To16()
}

func BroadcastIpv4Addr(n net.IPNet) net.IP {
	broadcast := net.IPv4zero.To4()
	ip4 := n.IP.To4()
	var mask net.IPMask
	if len(n.Mask) == 16 {
		mask = n.Mask[12:]
	} else {
		mask = n.Mask
	}

	for i := 0; i < len(ip4); i++ {
		broadcast[i] = ip4[i] | ^mask[i]
	}
	return broadcast.To16()
}

func IncrementIP(ip net.IP) net.IP {
	result := make(net.IP, len(ip))

	carry := true
	for i := len(ip) - 1; i >= 0; i-- {
		result[i] = ip[i]
		if carry {
			result[i]++
			if result[i] != 0 {
				carry = false
			}
		}
	}
	return result.To16()
}

func AlignNetMask(ip net.IP, mask net.IPMask) (net.IP, net.IPMask) {
	// Ensure 16 bytes representation
	ip16 := ip.To16()
	if len(mask) != len(ip16) && len(mask) == net.IPv4len {
		mask16 := make(net.IPMask, len(ip16))
		copy(mask16, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
		mask16[12] = mask[0]
		mask16[13] = mask[1]
		mask16[14] = mask[2]
		mask16[15] = mask[3]

		return ip16, mask16
	}
	return ip, mask
}
