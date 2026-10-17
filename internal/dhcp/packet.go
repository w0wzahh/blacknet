// Package dhcp implements a minimal, opt-in DHCPv4 server for Mode B
// (Blacknet-managed DHCP). It is disabled by default and must be explicitly
// enabled; enabling validates the interface and warns about existing servers.
package dhcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// DHCPv4 wire format constants.
const (
	opRequest   = 1
	opReply     = 2
	htypeEth    = 1
	bcastFlag   = 0x8000
	magicCookie = 0x63825363

	msgDiscover = 1
	msgOffer    = 2
	msgRequest  = 3
	msgDecline  = 4
	msgAck      = 5
	msgNak      = 6
	msgRelease  = 7

	optSubnetMask   = 1
	optRouter       = 3
	optDNS          = 6
	optHostname     = 12
	optRequestedIP  = 50
	optLeaseTime    = 51
	optMsgType      = 53
	optServerID     = 54
	optParamRequest = 55
	optEnd          = 255
	optPad          = 0
)

// Packet is a decoded DHCPv4 message (fixed header + options map).
type Packet struct {
	Op      byte
	XID     uint32
	Secs    uint16
	Flags   uint16
	CIAddr  net.IP
	YIAddr  net.IP
	SIAddr  net.IP
	GIAddr  net.IP
	CHAddr  net.HardwareAddr
	Options map[byte][]byte
}

// Parse decodes a raw DHCPv4 datagram.
func Parse(b []byte) (*Packet, error) {
	if len(b) < 240 {
		return nil, errors.New("packet too short")
	}
	if b[236] != 0x63 || b[237] != 0x82 || b[238] != 0x53 || b[239] != 0x63 {
		return nil, errors.New("bad magic cookie")
	}
	p := &Packet{
		Op:      b[0],
		XID:     binary.BigEndian.Uint32(b[4:8]),
		Secs:    binary.BigEndian.Uint16(b[8:10]),
		Flags:   binary.BigEndian.Uint16(b[10:12]),
		CIAddr:  dupIP(b[12:16]),
		YIAddr:  dupIP(b[16:20]),
		SIAddr:  dupIP(b[20:24]),
		GIAddr:  dupIP(b[24:28]),
		CHAddr:  dup(b[28:34]),
		Options: map[byte][]byte{},
	}
	for i := 240; i < len(b); {
		code := b[i]
		if code == optPad {
			i++
			continue
		}
		if code == optEnd {
			break
		}
		if i+2 > len(b) {
			break
		}
		l := int(b[i+1])
		if i+2+l > len(b) {
			return nil, errors.New("truncated option")
		}
		p.Options[code] = dup(b[i+2 : i+2+l])
		i += 2 + l
	}
	return p, nil
}

// MsgType returns the DHCP message type option (0 if absent).
func (p *Packet) MsgType() byte {
	if v, ok := p.Options[optMsgType]; ok && len(v) == 1 {
		return v[0]
	}
	return 0
}

// RequestedIP returns option 50 as an IP if present.
func (p *Packet) RequestedIP() net.IP {
	if v, ok := p.Options[optRequestedIP]; ok && len(v) == 4 {
		return net.IP(v)
	}
	return nil
}

// Hostname returns option 12 if present.
func (p *Packet) Hostname() string {
	if v, ok := p.Options[optHostname]; ok {
		return string(v)
	}
	return ""
}

// RequestedParams returns the option 55 list.
func (p *Packet) RequestedParams() []byte {
	return p.Options[optParamRequest]
}

// Reply builds a response packet to p.
func (p *Packet) Reply(msgType byte, yiaddr, serverIP net.IP, leaseSecs uint32,
	mask, router, dnsIP net.IP) []byte {
	out := make([]byte, 240, 312)
	out[0] = opReply
	out[1] = htypeEth
	out[2] = 6 // hlen
	binary.BigEndian.PutUint32(out[4:8], p.XID)
	binary.BigEndian.PutUint16(out[10:12], p.Flags)
	copy(out[16:20], yiaddr.To4())
	copy(out[28:34], p.CHAddr)
	binary.BigEndian.PutUint32(out[236:240], magicCookie)

	var opts []byte
	opts = append(opts, optMsgType, 1, msgType)
	opts = append(opts, optServerID, 4)
	opts = append(opts, serverIP.To4()...)
	opts = append(opts, optLeaseTime, 4)
	var lt [4]byte
	binary.BigEndian.PutUint32(lt[:], leaseSecs)
	opts = append(opts, lt[:]...)
	if mask != nil {
		opts = append(opts, optSubnetMask, 4)
		opts = append(opts, mask...)
	}
	if router != nil {
		opts = append(opts, optRouter, 4)
		opts = append(opts, router.To4()...)
	}
	if dnsIP != nil {
		opts = append(opts, optDNS, 4)
		opts = append(opts, dnsIP.To4()...)
	}
	// Renew/rebind timers at 50%/87.5% of lease.
	opts = append(opts, 58, 4)
	binary.BigEndian.PutUint32(lt[:], leaseSecs/2)
	opts = append(opts, lt[:]...)
	opts = append(opts, 59, 4)
	binary.BigEndian.PutUint32(lt[:], leaseSecs*7/8)
	opts = append(opts, lt[:]...)
	opts = append(opts, optEnd)
	out = append(out, opts...)
	return out
}

func dup(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func dupIP(b []byte) net.IP {
	ip := make(net.IP, 4)
	copy(ip, b)
	return ip
}

// MacString renders the client hardware address.
func (p *Packet) MacString() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		p.CHAddr[0], p.CHAddr[1], p.CHAddr[2], p.CHAddr[3], p.CHAddr[4], p.CHAddr[5])
}
