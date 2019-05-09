package dhcpd

import (
	"fmt"
	"net"
	"time"

	oc "github.com/caffeinetv/citadel/model/openconfig"
	"github.com/caffeinetv/citadel/pkg/inventory"
	"go.universe.tf/netboot/dhcp4"
)

var (
	defaultDHCPLeaseTime = 5 * time.Minute
)

func NewServer() *Server {
	ret := &Server{
		Port: 67,
	}
	return ret
}

// A Server boots machines using a Booter.
type Server struct {
	// Address to listen on, or empty for all interfaces.
	Address string

	// Log receives logs on Pixiecore's operation. If nil, logging
	// is suppressed.
	Log func(subsystem, msg string)
	// Debug receives extensive logging on Pixiecore's internals. Very
	// useful for debugging, but very verbose.
	Debug func(subsystem, msg string)

	// These ports can technically be set for testing, but the
	// protocols burned in firmware on the client side hardcode these,
	// so if you change them in production, nothing will work.
	Port int

	// support managing 1 set of mac:ip
	StaticMac  net.HardwareAddr
	StaticIPv4 net.IP
	DefaultURL string
	Inv        *inventory.Client
	Me         *oc.Device

	errs chan error
}

// Serve listens for machines attempting to boot, and responds to // their DHCPv6 requests.
func (s *Server) Serve() error {
	s.log("DHCP", "starting...")

	dhcp, err := dhcp4.NewConn(fmt.Sprintf("%s:%d", s.Address, s.Port))
	if err != nil {
		return err
	}

	s.debug("DHCP", "new connection...")

	// 5 buffer slots, one for each goroutine, plus one for
	// Shutdown(). We only ever pull the first error out, but shutdown
	// will likely generate some spurious errors from the other
	// goroutines, and we want them to be able to dump them without
	// blocking.
	s.errs = make(chan error, 6)

	go func() { s.errs <- s.serveDHCP(dhcp) }()

	// Wait for either a fatal error, or Shutdown().
	err = <-s.errs
	dhcp.Close()

	s.log("DHCP", "stopped...")
	return err
}

// Shutdown causes Serve() to exit, cleaning up behind itself.
func (s *Server) Shutdown() {
	select {
	case s.errs <- nil:
	default:
	}
}

func (s *Server) log(subsystem, format string, args ...interface{}) {
	if s.Log == nil {
		return
	}
	s.Log(subsystem, fmt.Sprintf(format, args...))
}

func (s *Server) debug(subsystem, format string, args ...interface{}) {
	if s.Debug == nil {
		return
	}
	s.Debug(subsystem, fmt.Sprintf(format, args...))
}
