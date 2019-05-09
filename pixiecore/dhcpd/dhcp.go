package dhcpd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/caffeinetv/citadel/model/iface"
	"github.com/caffeinetv/citadel/pkg/inventory"
	"go.universe.tf/netboot/dhcp4"
)

// serveDHCP only handle the PXE portion of the DHCP process not the
// initial network configuration bootstrapping of the interfaces
// TODO: currently not keeping tracks of transitions, assuming all requests are
// only from the oob-mgmt
func (s *Server) serveDHCP(conn *dhcp4.Conn) error {
	for {
		pkt, intf, err := conn.RecvDHCP()
		if err != nil {
			return fmt.Errorf("Receiving DHCP packet: %s", err)
		}
		if intf == nil {
			return fmt.Errorf("Received DHCP packet with no interface information (this is a violation of dhcp4.Conn's contract, please file a bug)")
		}

		if err = s.isStaticMAC(pkt); err != nil {
			s.debug("DHCP", "Ignoring packet from %s: %s", pkt.HardwareAddr, err)
			continue
		}

		// TODO the incoming intf could be either bondN or swpN, need to handle
		// both
		if err = s.isStaticPort(pkt, intf); err != nil {
			s.debug("DHCP", "Ignoring packet from %s: %s", pkt.HardwareAddr, err)
			continue
		}

		// Machine should be booted.
		serverIP, err := interfaceIP(intf)
		if err != nil {
			s.log("DHCP", "Want to boot %s on %s, but couldn't get a source address: %s", pkt.HardwareAddr, intf.Name, err)
			continue
		}
		// TODO: DHCP transitions

		// NOTE: rapid commit mode[1], out of spec, since we sending Offer/Ack
		// whether the client support it or not.
		// typical DHCP flow: discover -> request -> ack
		// rapid commit: discover -> (request,ack)
		// [1] https://tools.ietf.org/html/rfc4039
		if pkt.Type == dhcp4.MsgDiscover {
			s.log("DHCP", "%s request found %s on %s", pkt.Type, pkt.HardwareAddr, intf.Name)
			// return fmt.Errorf("packet is %s, not %s", pkt.Type, dhcp4.MsgDiscover)
			resp, err := s.offerDHCP(pkt, serverIP, intf)
			if err != nil {
				s.log("DHCP", "Failed to construct DHCP offer for %s: %s", pkt.HardwareAddr, err)
				continue
			}

			if err = conn.SendDHCP(resp, intf); err != nil {
				s.log("DHCP", "Failed to send DHCP offer for %s: %s", pkt.HardwareAddr, err)
				continue
			}
		}

		s.debug("DHCP", "got valid %s, responding with ACK", pkt.Type)
		resp, err := s.ackDHCP(pkt, serverIP, intf)
		if err != nil {
			s.log("DHCP", "Failed to construct DHCP offer for %s: %s", pkt.HardwareAddr, err)
			continue
		}

		s.debug("DHCP", "sending response to %s, %s", resp.HardwareAddr, resp.Options)
		if err = conn.SendDHCP(resp, intf); err != nil {
			s.log("DHCP", "Failed to send DHCP offer for %s: %s", pkt.HardwareAddr, err)
			continue
		}
	}
}

func (s *Server) defaultURL(pkt *dhcp4.Packet, serverIP net.IP, intf *net.Interface, hostname string) string {
	baseURL := "http://%s/"
	if len(s.DefaultURL) == 0 {
		baseURL = fmt.Sprintf("http://%s:%d/", serverIP, 80)
	}

	path, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	path.Path += "_/ztp"
	parameters := url.Values{}
	parameters.Add("vendor", "cumulus")
	parameters.Add("mac", pkt.HardwareAddr.String())
	parameters.Add("port", intf.Name)
	parameters.Add("hostname", hostname)
	path.RawQuery = parameters.Encode()

	return path.String()
}

func (s *Server) staticIP() net.IP {
	return s.StaticIPv4
}

// getIP return the v4 address and mask
func (s *Server) getIP(intf *net.Interface) (string, net.IP, net.IPMask, error) {
	s.log("DHCP", "getting host info for interface %s", intf.Name)

	// found that this request is coming from a valid port
	i, ok := s.Me.Interface[intf.Name]
	if !ok {
		return "", nil, nil, errors.New("unable to find interface")
	}

	if len(i.ΛMetadata) == 0 {
		return "", nil, nil, errors.New("unable to find ip")
	}
	meta := i.ΛMetadata[0].(*iface.Metadata)

	// now need to find the IP to give it, local interface most likely not to
	// have the ip, find the IP from the remote connecting interface
	ip, err := inventory.IP(
		s.Inv.Single(meta.RemoteHost),
		meta.RemoteIface,
	)
	if err != nil {
		s.log("DHCP", "no matching interface found", intf.Name)
		fmt.Println("no IP found", meta.RemoteIface, meta.RemoteHost, err)
		return "", nil, nil, errors.New("unable to find ip")
	}

	ipAddr, ipNet, err := net.ParseCIDR(ip)
	if err != nil {
		return "", nil, nil, errors.New("unable to parse IP cidr")
	}
	return meta.RemoteHost, ipAddr, ipNet.Mask, nil
}

// isStaticPort ensure that if a static port mapping is set, the incoming port
// has to match
func (s *Server) isStaticPort(pkt *dhcp4.Packet, intf *net.Interface) error {
	if _, ok := s.Me.Interface[intf.Name]; !ok {
		return errors.New("no matching port found")
	}

	return nil
}

// isStaticMAC ensure that if a static mac address is set, the incoming mac
// has to match
func (s *Server) isStaticMAC(pkt *dhcp4.Packet) error {
	if bytes.Compare(s.StaticMac, nil) == 0 {
		return nil
	}

	if bytes.Compare(s.StaticMac, pkt.HardwareAddr) != 0 {
		return fmt.Errorf("required hardware address %s, packet is %s, found %s", s.StaticMac, pkt.Type, pkt.HardwareAddr)
	}

	return nil
}

func (s *Server) ackDHCP(pkt *dhcp4.Packet, serverIP net.IP, intf *net.Interface) (*dhcp4.Packet, error) {
	resp := &dhcp4.Packet{
		Type:          dhcp4.MsgAck,
		TransactionID: pkt.TransactionID,
		Broadcast:     true,
		HardwareAddr:  pkt.HardwareAddr,
		RelayAddr:     pkt.RelayAddr,
		ServerAddr:    serverIP,
		Options:       make(dhcp4.Options),
	}
	resp.Options[dhcp4.OptServerIdentifier] = serverIP
	// // says the server should identify itself as a PXEClient vendor
	// // type, even though it's a server. Strange.
	// resp.Options[dhcp4.OptVendorIdentifier] = []byte("PXEClient")
	// if pkt.Options[97] != nil {
	// 	resp.Options[97] = pkt.Options[97]
	// }

	s.log("DHCP", "getting ip for interface %s", intf.Name)
	// setting up default mask
	hostname, ip, mask, err := s.getIP(intf)
	if err != nil {
		return nil, errors.New("unable to assign IP and network")
	}

	resp.YourAddr = ip
	resp.Options[1] = mask
	resp.Options[12] = []byte(hostname)
	resp.Options[51] = optionsLeaseTime(defaultDHCPLeaseTime)
	resp.Options[239] = []byte(s.defaultURL(pkt, serverIP, intf, hostname))
	resp.BootServerName = serverIP.String()

	return resp, nil
}

// optionsLeaseTime - converts a time.Duration to a 4 byte slice, compatible
// with OptionIPAddressLeaseTime.
func optionsLeaseTime(d time.Duration) []byte {
	leaseBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(leaseBytes, uint32(d/time.Second))
	return leaseBytes
}

func (s *Server) offerDHCP(pkt *dhcp4.Packet, serverIP net.IP, intf *net.Interface) (*dhcp4.Packet, error) {
	resp := &dhcp4.Packet{
		Type:          dhcp4.MsgOffer,
		TransactionID: pkt.TransactionID,
		Broadcast:     true,
		HardwareAddr:  pkt.HardwareAddr,
		RelayAddr:     pkt.RelayAddr,
		ServerAddr:    serverIP,
		Options:       make(dhcp4.Options),
	}
	resp.Options[dhcp4.OptServerIdentifier] = serverIP
	// // says the server should identify itself as a PXEClient vendor
	// // type, even though it's a server. Strange.
	// resp.Options[dhcp4.OptVendorIdentifier] = []byte("PXEClient")
	// if pkt.Options[97] != nil {
	// 	resp.Options[97] = pkt.Options[97]
	// }
	hostname, ip, mask, err := s.getIP(intf)
	if err != nil {
		return nil, errors.New("unable to assign IP and network")
	}

	resp.YourAddr = ip
	resp.Options[1] = mask
	resp.Options[51] = optionsLeaseTime(defaultDHCPLeaseTime)
	resp.Options[239] = []byte(s.defaultURL(pkt, serverIP, intf, hostname))
	resp.BootServerName = serverIP.String()

	return resp, nil
}

func interfaceIP(intf *net.Interface) (net.IP, error) {
	addrs, err := intf.Addrs()
	if err != nil {
		return nil, err
	}

	// Try to find an IPv4 address to use, in the following order:
	// global unicast (includes rfc1918), link-local unicast,
	// loopback.
	fs := [](func(net.IP) bool){
		net.IP.IsGlobalUnicast,
		net.IP.IsLinkLocalUnicast,
		net.IP.IsLoopback,
	}
	for _, f := range fs {
		for _, a := range addrs {
			ipaddr, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipaddr.IP.To4()
			if ip == nil {
				continue
			}
			if f(ip) {
				return ip, nil
			}
		}
	}

	return nil, errors.New("no usable unicast address configured on interface")
}
