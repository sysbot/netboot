// Copyright 2016 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pixiecore

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// parseCumulusHeaders convert the Mime type headers into map
// Header                        Value                 Example
// ------                        -----                 -------
// User-Agent                                          CumulusLinux-AutoProvision/0.4
// CUMULUS-ARCH                  CPU architecture      x86_64
// CUMULUS-BUILD                                       3.7.3-5c6829a-201309251712-final
// CUMULUS-LICENSE-INSTALLED     Either 0 or 1         1
// CUMULUS-MANUFACTURER                                odm
// CUMULUS-PRODUCTNAME                                 switch_model
// CUMULUS-SERIAL                                      XYZ123004
// CUMULUS-BASE-MAC                                    44:38:39:FF:40:94
// CUMULUS-MGMT-MAC                                    44:38:39:FF:00:00
// CUMULUS-VERSION                                     3.7.3
// CUMULUS-PROV-COUNT                                  0
// CUMULUS-PROV-MAX                                    32
// [1] https://docs.cumulusnetworks.com/display/DOCS/Zero+Touch+Provisioning+-+ZTP
func parseCumulusHeaders(req *http.Request) map[string]string {
	ret := map[string]string{}
	for k, v := range extractMimeHeaders(req) {
		s := strings.ToLower(k)
		if !strings.HasPrefix(s, "cumulus") {
			continue
		}
		if len(v) == 0 {
			continue
		}

		ret[s] = v[0]
	}

	return ret
}

func extractMimeHeaders(req *http.Request) textproto.MIMEHeader {
	d, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil
	}

	reader := bufio.NewReader(bytes.NewReader(d))
	tp := textproto.NewReader(reader)

	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil
	}

	return mimeHeader
}

// handleZTP
func (s *Server) handleZTP(w http.ResponseWriter, r *http.Request) {
	overallStart := time.Now()
	rURL := strings.Replace(r.URL.String(), `\`, "", -1)
	sURL, err := url.Parse(rURL)
	if err != nil {
		s.debug("HTTP", "Bad request %q from %s, invalid request url (%s)", r.URL, r.RemoteAddr, rURL)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	vendorStr := sURL.Query().Get("vendor")
	if vendorStr == "" {
		s.debug("HTTP", "Bad request %q from %s, missing Vendor identifier", sURL, r.RemoteAddr)
		http.Error(w, "missing Vendor identifier parameter", http.StatusBadRequest)
		return
	}

	var meta map[string]string
	switch vendorStr {
	case "cumulus":
		s.debug("HTTP", "potential ZTP request %q from %s", sURL, r.RemoteAddr)
		meta = parseCumulusHeaders(r)
		s.debug("HTTP", "request %q from %s, header dump %s", sURL, r.RemoteAddr, meta)
	default:
		s.debug("HTTP", "Bad request %q from %s, unknown vendor %q", sURL, r.RemoteAddr, vendorStr)
		http.Error(w, "unknown vendor", http.StatusBadRequest)
	}

	arch := ArchX64
	archStr := sURL.Query().Get("arch")
	if archStr == "" {
		s.debug("HTTP", "request %q from %s, missing architecture, continue...", sURL, r.RemoteAddr)
	} else {
		i, err := strconv.Atoi(archStr)
		if err != nil {
			s.debug("HTTP", "Bad request %q from %s, invalid architecture %q (%s)", sURL, r.RemoteAddr, archStr, err)
			http.Error(w, "invalid architecture", http.StatusBadRequest)
			return
		}

		arch = Architecture(i)
		switch arch {
		case ArchIA32, ArchX64:
		default:
			s.debug("HTTP", "Bad request %q from %s, unknown architecture %q", sURL, r.RemoteAddr, arch)
			http.Error(w, "unknown architecture", http.StatusBadRequest)
			return
		}
	}

	portStr := sURL.Query().Get("port")
	if portStr == "" {
		s.debug("HTTP", "request %q from %s, missing port %s, continue...", sURL, r.RemoteAddr, portStr)
	}

	var mac net.HardwareAddr
	// TODO: the mac/ip address pair from the requesting Host should be use to track
	// future states and callbacks
	macStr := sURL.Query().Get("mac")
	if macStr == "" {
		s.debug("HTTP", "request %q from %s, missing MAC address, continue", sURL, r.RemoteAddr)
	} else {
		var err error
		mac, err = net.ParseMAC(macStr)
		if err != nil {
			s.debug("HTTP", "Bad request %q from %s, invalid MAC address %q (%s)", sURL, r.RemoteAddr, macStr, err)
			// http.Error(w, "invalid MAC address", http.StatusBadRequest)
			// return
		}
	}

	// allowing to override the IP address from the URL
	ip := net.ParseIP(r.RemoteAddr)
	ipStr := sURL.Query().Get("ip")
	if ipStr == "" {
		s.debug("HTTP", "request %q from %s, missing IP %s", sURL, r.RemoteAddr, ipStr)
	} else {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			s.debug("HTTP", "request %q from %s, no valid IP address found %q, using request address %s", sURL, r.RemoteAddr, ip, r.RemoteAddr)
			http.Error(w, "invalid IP address", http.StatusBadRequest)
			return
		}
	}

	ifName := sURL.Query().Get("ifname")
	if ifName == "" {
		s.debug("HTTP", "request %q from %s, missing Ifname %s", sURL, r.RemoteAddr, ifName)
	}

	// if the hostname exist, use it to overwrite the ip and ifname
	hostname := sURL.Query().Get("hostname")
	if hostname == "" {
		s.debug("HTTP", "request %q from %s, missing HOSTNAME %s", sURL, r.RemoteAddr, hostname)
		http.Error(w, "missing required hostname", http.StatusBadRequest)
		return
	} else {
		if meta != nil {
			meta["CAFFEINE_HOSTNAME"] = hostname
		}
	}

	mach := Machine{
		MAC:      mac,
		Arch:     arch,
		IP:       ip,
		Iface:    &net.Interface{Name: ifName},
		Metadata: meta,
	}
	start := time.Now()
	spec, err := s.Booter.BootSpec(mach)
	s.debug("HTTP", "Get bootspec for %s took %s", mach, time.Since(start))
	if err != nil {
		s.log("HTTP", "Couldn't get a bootspec for %s (query %q from %s): %s", mac, sURL, r.RemoteAddr, err)
		http.Error(w, "couldn't get a bootspec", http.StatusInternalServerError)
		return
	}
	if spec == nil {
		// TODO: make ipxe abort netbooting so it can fall through to
		// other boot options - unsure if that's possible.
		s.debug("HTTP", "No boot spec for %s (query %q from %s), ignoring boot request", mac, sURL, r.RemoteAddr)
		http.Error(w, "you don't netboot", http.StatusNotFound)
		return
	}
	start = time.Now()
	script, err := ztpScript(mach, spec)
	s.debug("HTTP", "Construct ZTP script for %s took %s", mac, time.Since(start))
	if err != nil {
		s.log("HTTP", "Failed to assemble ZTP script for %s (query %q from %s): %s", mac, sURL, r.RemoteAddr, err)
		http.Error(w, "couldn't get a boot script", http.StatusInternalServerError)
		return
	}

	// s.log("HTTP", "script %s", script)
	s.log("HTTP", "Sending ZTP boot script to %s", r.RemoteAddr)
	start = time.Now()
	s.machineEvent(mac, machineStateZTP, "Sent ZTP boot script")
	w.Header().Set("Content-Type", "text/plain")
	w.Write(script)
	s.debug("HTTP", "Writing ZTP script to %s took %s", mac, time.Since(start))
	s.debug("HTTP", "handleZTP for %s took %s", mac, time.Since(overallStart))
}

// ztpScript return the ZTP bootstrapping script needed by Cumulus ZTP process
func ztpScript(mach Machine, spec *Spec) ([]byte, error) {
	// ipxescript will be a template for ztp
	if spec.IpxeScript != "" {
		return []byte(spec.IpxeScript), nil
	}
	return nil, nil
}
