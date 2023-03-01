package utils

import (
	"encoding/json"
	"net"
	"strconv"
)

// IPnMask Original IPNet truncates the non-masked side in some operations cause this type is meant to be a network
// address, not an IP with its network mask. No json encoding too.
type IPnMask struct {
	net.IPNet
}

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

func NewIPnMask(ip net.IP, mask net.IPMask) IPnMask {
	aIp, aMask := AlignNetMask(ip, mask)
	return IPnMask{net.IPNet{
		IP:   aIp,
		Mask: aMask,
	}}
}

func (i IPnMask) ToNet() net.IPNet {
	return net.IPNet{IP: i.IP.Mask(i.Mask), Mask: i.Mask}
}

func NewIPnMaskFromNet(network net.IPNet) IPnMask {
	return NewIPnMask(network.IP, network.Mask)
}

func (i IPnMask) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.String())
}

func (i IPnMask) String() string {
	var maskSize int
	// Mask, in IPnMask is always 16 bytes as it is aligned in creation to 16 bytes
	l, _ := i.Mask.Size()
	if l == -1 {
		return i.IP.String() + "/0"
	} else if ipv4 := i.IP.To4(); ipv4 != nil {
		// Is IPv4
		maskSize = 32 - (128 - l)
	} else {
		maskSize = l
	}

	return i.IP.String() + "/" + strconv.FormatUint(uint64(maskSize), 10)
}

func TryParseIPSlice(ips []string) []net.IP {
	parsedIPs := make([]net.IP, 0)
	for _, ipStr := range ips {
		ip, _, err := net.ParseCIDR(ipStr)
		if err != nil {
			continue
		}

		return append(parsedIPs, ip)
	}
	return parsedIPs
}

func TryParseNetSlice(nets []string) []net.IPNet {
	parsedNets := make([]net.IPNet, 0)
	for _, netStr := range nets {
		_, net, err := net.ParseCIDR(netStr)
		if err != nil || net == nil {
			continue
		}

		return append(parsedNets, *net)
	}
	return parsedNets
}
