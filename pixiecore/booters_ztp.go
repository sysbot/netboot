package pixiecore

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"text/template"

	"github.com/caffeinetv/citadel/model/iface"
	"github.com/caffeinetv/citadel/model/machine"
	"github.com/caffeinetv/citadel/pkg/inventory"
	"github.com/gobuffalo/packr"
	"github.com/openconfig/ygot/ygot"
)

var (
	defaultInstallScript     = "install.sh.tpl"
	defaultLeafInstallScript = "install.leaf.sh.tpl"
	defaultMgmtInstallScript = "install.mgmt.sh.tpl"
)

// Ztpbooter gets a BootSpec from a remote server over HTTP.
// The API is described in README.api.md
func ZTPBooter(box *packr.Box, client *inventory.Client) (Booter, error) {
	return &ztpbooter{
		box: box,
		inv: client,
	}, nil
}

type ztpbooter struct {
	box *packr.Box
	inv *inventory.Client
}

// templateFile take take data and write out to dest based on source tmpl
// with optional funcMap
// template reference:
// . follow the function is the parameter
// with pipelin, the result of each command is the last argument to the following command
// command is allowed 1 or 2 values, if 2, second must be error
// with - switch current context, easier to use nested variable
// variable - {{$variable := pipeline}}
// {{range pipeline}} T {{end}}
// {{if pipeline}} T1 {{else}} T2 {{end}}
func expandZTPScript(tpl string, funcs template.FuncMap, data interface{}) (string, error) {
	t, err := template.New("install_script").Option("missingkey=error").Funcs(funcs).Parse(tpl)
	if err != nil {
		// Logger.Error("parsing", zap.Error(err))
		return "", fmt.Errorf("parsing template %q: %v", tpl, err)
	}

	// data interface is current context (denoted with .), is second parameter of tmpl.Execute
	var out bytes.Buffer
	if err = t.Execute(&out, data); err != nil {
		// Logger.Error("run template", zap.Error(err))
		return "", fmt.Errorf("expanding template %q: %s", tpl, err)
	}

	return out.String(), nil
}

type DefaultTemplate struct {
	NTPServer string `json:"ntp_server"`
}

type MgmtTemplate struct {
	ServerV4   string `json:"server_v4"`
	ServerV4Gw string `json:"server_v4_gateway"`
	BastionV4  string `json:"bastion_v4"`
	NTPServer  string `json:"ntp_server"`
	Vlan       string `json:"vlan"`
}

type LeafTemplate struct {
	ServerV4          string `json:"server_v4"`
	ServerV4Gw        string `json:"server_v4_gateway"`
	NTPServer         string `json:"ntp_server"`
	Vlan              string `json:"vlan"`
	ShepardV4         string `json:"shepard_v4"`
	ServerV6          string `json:"server_v6"`
	ServerV6Gw        string `json:"server_v6_gateway"`
	IGMPQuerierSource string `json:"igmp_querier_source"`
	IPMIV4            string `json:"ipmi_v4"`
}

// Iface represent the network interface configs
type Iface struct {
	Lag         bool   `json:"lag"`
	MulticastV4 string `json:"multicast_v4"`
	RemoteIP    string `json:"remote_ip"`
	Ports       string `json:"ports"`
	Vlan        string `json:"vlan"`
}

func formatAsString(i int) string {
	return fmt.Sprintf("%d", i)
}

// BootSpec return the spec needed to netboot
func (b *ztpbooter) BootSpec(m Machine) (*Spec, error) {
	var (
		out string
	)

	n := ""
	if _, ok := m.Metadata["CAFFEINE_HOSTNAME"]; !ok {
		// return nil, errors.New("missing hostname")
		n = "default"
		fmt.Println("missing hostname, using default: ", n)
	} else {
		n = m.Metadata["CAFFEINE_HOSTNAME"]
	}

	// depending on when in mgmt mode, or leaf mode
	// switch based on the ipxe template or the ztp template to use
	// currently this would fail, if s0 is input instead of oob-mgmt
	// ex:
	// when oob-mgmt, in ztp, there's no fremont-0-0 connected
	// when fremont-0-s0, in ipxe, there's no fremont-0-s0 connected
	hostMatch := strings.ToLower(n)

	host := b.inv.Single(hostMatch)
	if host == nil {
		// return nil, errors.New("host not found")
		host = machine.New(
			n,
			[]ygot.Annotation{
				&machine.Metadata{
					ID:      0,
					Serial:  "default",
					Profile: "default",
					Site:    "default",
					Name:    n,
				},
			},
		)
		fmt.Println("no host found, creating a default...", host)
	}

	// this function generate the map of host to remote host and interfaces
	mgmtIface := func() map[string]Iface {
		interfaces := map[string]Iface{}
		fmt.Println("interfaces: ", host.Interface)
		for i, v := range host.Interface {
			fmt.Println("XXXX", i, v)
			if len(v.ΛMetadata) == 0 {
				continue
			}
			meta := v.ΛMetadata[0].(*iface.Metadata)
			vlan, err := inventory.Vlan(
				host,
				i,
			)
			if err != nil {
				fmt.Println("no vlan found", meta.RemoteIface, meta.RemoteHost, err)
				continue
			}
			d := b.inv.Single(meta.RemoteHost)
			if d == nil {
				continue
			}

			ip, err := inventory.IP(
				d,
				meta.RemoteIface,
			)
			if err != nil {
				fmt.Println("no ip found", meta.RemoteIface, meta.RemoteHost, err)
				continue
			}
			var lag bool
			if strings.HasPrefix(meta.RemoteIface, "bond") {
				lag = true
			}
			interfaces[i] = Iface{
				Lag:         lag,
				MulticastV4: "239.0.0.1",
				RemoteIP:    ip,
				Ports:       "",
				Vlan:        fmt.Sprintf("%d", *(vlan)),
			}
		}
		return interfaces
	}

	// TODO alot of this stuff should be done from the otherside of the API to
	// keep this interface pure and not having business logic, although the
	// business logic here are derivative of the "hosted" topology
	leafIface := func() map[string]Iface {
		interfaces := map[string]Iface{}
		fmt.Println("interfaces: ", host.Interface)
		for i, v := range host.Interface {
			if len(v.ΛMetadata) == 0 {
				fmt.Println("empty")
				continue
			}
			meta := v.ΛMetadata[0].(*iface.Metadata)

			fmt.Println("XXXX", host, i)
			// remote host is required here since we looking at the switches
			// which mean each port has to connect at least a remote device
			d := b.inv.Single(meta.RemoteHost)
			if d == nil {
				continue
			}

			fmt.Println("XXXX single", d)
			// need the vlan and lag members of each connecting ports
			vlan, err := inventory.Vlan(
				host,
				i,
			)
			if err != nil {
				fmt.Println("no vlan found", meta.RemoteIface, meta.RemoteHost, err)
				continue
			}
			fmt.Println("XXXX vlan", vlan)
			ports, err := inventory.LagMembers(
				host,
				i,
			)
			if err != nil {
				fmt.Println("no members found", meta.RemoteIface, meta.RemoteHost, err)
				continue
			}

			fmt.Println("XXXX ports", ports)
			// need the IP of the remote connecting machine
			ip, err := inventory.IP(
				d,
				meta.RemoteIface,
			)
			if err != nil {
				fmt.Println("no IP found", meta.RemoteIface, meta.RemoteHost, err)
				continue
			}

			fmt.Println("XXXX ip", ip)
			var lag bool
			if strings.HasPrefix(meta.RemoteIface, "bond") {
				lag = true
			}

			fmt.Println("XXXX interfaces", lag, ip, ports, vlan)
			interfaces[i] = Iface{
				Lag:         lag,
				MulticastV4: "239.0.0.1",
				RemoteIP:    ip,
				Ports:       strings.Join(ports, " "),
				Vlan:        fmt.Sprintf("%d", *(vlan)),
			}
		}
		fmt.Println("XXXX: interfaces ", interfaces)
		return interfaces
	}

	meta := host.ΛMetadata[0].(*machine.Metadata)
	switch strings.ToLower(meta.Profile) {
	case "management":
		mainIP, err := inventory.IP(
			host,
			"vlan_main",
		)
		if err != nil {
			return nil, fmt.Errorf("no IP found", "vlan_main", err)
		}
		fmt.Println("XXXX mainip", mainIP)
		vlan, err := inventory.Vlan(
			host,
			"vlan_main",
		)
		if err != nil {
			return nil, fmt.Errorf("no vlan found", "vlan_main", err)
		}
		fmt.Println("XXXX vlan", vlan)
		// management things
		out, err = expandZTPScript(
			b.box.String(defaultMgmtInstallScript),
			template.FuncMap{
				"MgmtInterfaces": mgmtIface,
				"formatAsString": formatAsString,
			},
			MgmtTemplate{
				ServerV4:   mainIP,
				ServerV4Gw: "10.2.0.1",
				BastionV4:  "10.3.0.251",
				NTPServer:  "clock.fmt.he.net",
				Vlan:       fmt.Sprintf("%d", int(*(vlan))),
			},
		)
		if err != nil {
			return nil, fmt.Errorf(
				"expanding ztp script %q: %v", defaultMgmtInstallScript, err)
		}
	case "leaf":
		// leaf things
		// vlan, err := inventory.Vlan(
		// 	host,
		// 	"vlan_main",
		// )
		// if err != nil {
		// 	fmt.Println("no vlan found", "vlan_main", err)
		// 	continue
		// }
		gw, iface, err := inventory.Gateway(
			host,
			"0.0.0.0/0",
		)
		if err != nil {
			return nil, fmt.Errorf("no default routes found", host, err)
		}
		fmt.Println("XXXX gw iface", gw, iface)
		mainIP, err := inventory.IP(
			host,
			"vlan_main",
		)
		if err != nil {
			return nil, fmt.Errorf("no IP found", "vlan_main", err)
		}
		fmt.Println("XXXX mainip", mainIP)
		ipmiIP, err := inventory.IP(
			host,
			"vlan_ipmi",
		)
		if err != nil {
			return nil, fmt.Errorf("no IP found", "vlan_ipmi", err)
		}
		fmt.Println("XXXX ipmiip", ipmiIP)
		out, err = expandZTPScript(
			b.box.String(defaultLeafInstallScript),
			template.FuncMap{
				"LeafInterfaces": leafIface,
				"formatAsString": formatAsString,
			},
			LeafTemplate{
				// TODO: the reponsible igmp querier of the lan
				IGMPQuerierSource: "64.62.206.30",
				ServerV4:          mainIP,
				ServerV4Gw:        gw,
				// TODO localize region, system/component
				NTPServer:  "clock.fmt.he.net",
				Vlan:       "1",
				ServerV6:   "2001:470:127:27:ffff:ffff:ffff:fffe/64",
				ServerV6Gw: "2001:470:127:27::1",
				IPMIV4:     ipmiIP,
				// mgmt0/eth0 is not configured here as it's using the DHCP address
			},
		)
		if err != nil {
			return nil, fmt.Errorf(
				"expanding ztp script %q: %v", defaultLeafInstallScript, err)
		}
	case "default":
		var err error
		out, err = expandZTPScript(
			b.box.String(defaultInstallScript),
			template.FuncMap{
				"formatAsString": formatAsString,
			},
			DefaultTemplate{
				// TODO localize region, system/component
				NTPServer: "clock.fmt.he.net",
				// mgmt0/eth0 is not configured here as it's using the DHCP address
			},
		)
		if err != nil {
			return nil, fmt.Errorf(
				"expanding ztp script %q: %v", defaultInstallScript, err)
		}
	default:
		return nil, fmt.Errorf("unknown profile")
	}

	return &Spec{
		IpxeScript: out,
	}, nil
}

func (b *ztpbooter) ReadBootFile(id ID) (io.ReadCloser, int64, error) {
	// urlStr, err := getURL(id, &b.key)
	// if err != nil {
	// 	return nil, -1, err
	// }

	// TODO onie-installer-x86_64-cumulus_vx-r0.bin
	// TODO onie-installer-x86_64.bin

	// u, err := url.Parse(urlStr)
	// if err != nil {
	// 	return nil, -1, fmt.Errorf("%q is not an URL", urlStr)
	// }
	var (
		ret io.ReadCloser
		sz  int64 = -1
	)
	// if u.Scheme == "file" {
	// 	// TODO serveFile
	// 	f, err := os.Open(u.Path)
	// 	if err != nil {
	// 		return nil, -1, err
	// 	}
	// 	fi, err := f.Stat()
	// 	if err != nil {
	// 		f.Close()
	// 		return nil, -1, err
	// 	}
	// 	ret, sz = f, fi.Size()
	// } else {
	// 	// urlStr will get reparsed by http.Get, which is mildly
	// 	// wasteful, but the code looks nicer than constructing a
	// 	// Request.
	// 	resp, err := http.Get(urlStr)
	// 	if err != nil {
	// 		return nil, -1, err
	// 	}
	// 	if resp.StatusCode != 200 {
	// 		return nil, -1, fmt.Errorf("GET %q failed: %s", urlStr, resp.Status)
	// 	}

	// 	ret, sz, err = resp.Body, resp.ContentLength, nil
	// }
	// if err != nil {
	// 	return nil, -1, err
	// }
	return ret, sz, nil
}

func (b *ztpbooter) WriteBootFile(id ID, body io.Reader) error {
	// u, err := getURL(id, &b.key)
	// if err != nil {
	// 	return err
	// }

	// resp, err := http.Post(u, "application/octet-stream", body)
	// if err != nil {
	// 	return err
	// }
	// if resp.StatusCode != 200 {
	// 	return fmt.Errorf("POST %q failed: %s", u, resp.Status)
	// }
	// defer resp.Body.Close()
	return nil
}

// func (b *ztpbooter) makeURLAbsolute(urlStr string) (string, error) {
// 	u, err := url.Parse(urlStr)
// 	if err != nil {
// 		return "", fmt.Errorf("%q is not an URL", urlStr)
// 	}
// 	if !u.IsAbs() {
// 		base, err := url.Parse(b.urlPrefix)
// 		if err != nil {
// 			return "", err
// 		}
// 		u = base.ResolveReference(u)
// 	}
// 	return u.String(), nil
// }

// func (b *ztpbooter) constructCmdline(m map[string]interface{}) (string, error) {
// 	var c []string
// 	for k := range m {
// 		c = append(c, k)
// 	}
// 	sort.Strings(c)

// 	var ret []string
// 	for _, k := range c {
// 		switch v := m[k].(type) {
// 		case bool:
// 			ret = append(ret, k)
// 		case string:
// 			ret = append(ret, fmt.Sprintf("%s=%q", k, v))
// 		case map[string]interface{}:
// 			urlStr, ok := v["url"].(string)
// 			if !ok {
// 				return "", fmt.Errorf("cmdline key %q has object value with no 'url' attribute", k)
// 			}
// 			ret = append(ret, fmt.Sprintf("%s={{ URL %q }}", k, urlStr))
// 		default:
// 			return "", fmt.Errorf("unsupported value kind %T for cmdline key %q", m[k], k)
// 		}
// 	}
// 	return strings.Join(ret, " "), nil
// }
