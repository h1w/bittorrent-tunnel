package portmap

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testSOAP = "http://schemas.xmlsoap.org/soap/envelope/"

func testDescription(service, control string) string {
	return `<root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:2</deviceType><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:2</deviceType><serviceList><service><serviceType>` + service + `</serviceType><controlURL>` + control + `</controlURL></service></serviceList></device></deviceList></device></deviceList></device></root>`
}

func testSOAPReply(w http.ResponseWriter, service, action, body string) {
	fmt.Fprintf(w, `<s:Envelope xmlns:s="%s"><s:Body><u:%sResponse xmlns:u="%s">%s</u:%sResponse></s:Body></s:Envelope>`, testSOAP, action, service, body, action)
}

func testSOAPFault(w http.ResponseWriter, code int) {
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `<s:Envelope xmlns:s="%s"><s:Body><s:Fault><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>%d</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>`, testSOAP, code)
}

func rejectNAT(t *testing.T, conn *net.UDPConn, packets <-chan gatewayPacket) {
	t.Helper()
	p := receive(t, packets)
	respond(t, conn, p, []byte{0, 128, 0, 1, 0, 0, 0, 22})
	p = receive(t, packets)
	respond(t, conn, p, []byte{0, 128, 0, 5, 0, 0, 0, 22})
}

func sendLocation(t *testing.T, conn *net.UDPConn, p gatewayPacket, location string) {
	t.Helper()
	respond(t, conn, p, []byte("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nLOCATION: "+location+"\r\n\r\n"))
}

func TestIGDRenewsAndDeletesOnlyVerifiedOwnedLease(t *testing.T) {
	for _, service := range []string{
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANIPConnection:2",
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
	} {
		t.Run(service, func(t *testing.T) {
			for _, replaced := range []bool{false, true} {
				t.Run(fmt.Sprintf("replaced=%t", replaced), func(t *testing.T) {
					t.Parallel()
					var mu sync.Mutex
					mapping := map[uint16]string{42300: "manual mapping"}
					var ownedPort uint16
					added := make(chan uint16, 3)
					deleted := make(chan uint16, 2)
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path == "/descriptions/igd.xml" && r.Method == http.MethodGet {
							fmt.Fprint(w, testDescription(service, "../control"))
							return
						}
						action := strings.TrimPrefix(strings.Trim(r.Header.Get("SOAPAction"), `"`), service+"#")
						var envelope struct {
							Body struct {
								Action struct {
									XMLName     xml.Name
									External    uint16 `xml:"NewExternalPort"`
									Internal    uint16 `xml:"NewInternalPort"`
									Client      string `xml:"NewInternalClient"`
									Protocol    string `xml:"NewProtocol"`
									Remote      string `xml:"NewRemoteHost"`
									Description string `xml:"NewPortMappingDescription"`
									Seconds     uint32 `xml:"NewLeaseDuration"`
									Enabled     uint8  `xml:"NewEnabled"`
								} `xml:",any"`
							}
						}
						err := xml.NewDecoder(r.Body).Decode(&envelope)
						a := envelope.Body.Action
						if r.URL.Path != "/control" || r.Method != http.MethodPost || err != nil || a.XMLName != (xml.Name{Space: service, Local: action}) {
							t.Errorf("invalid SOAP request: %s %s %q %+v, %v", r.Method, r.URL.Path, action, a, err)
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						mu.Lock()
						defer mu.Unlock()
						if action != "GetExternalIPAddress" && (a.Protocol != "UDP" || a.Remote != "" || a.External == 0) {
							t.Errorf("request is not for one UDP mapping: %+v", a)
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						switch action {
						case "GetExternalIPAddress":
							testSOAPReply(w, service, action, `<NewExternalIPAddress>8.8.8.8</NewExternalIPAddress>`)
						case "GetSpecificPortMappingEntry":
							if description, ok := mapping[a.External]; ok {
								testSOAPReply(w, service, action, `<NewInternalPort>42300</NewInternalPort><NewInternalClient>127.0.0.1</NewInternalClient><NewEnabled>1</NewEnabled><NewLeaseDuration>2</NewLeaseDuration><NewPortMappingDescription>`+description+`</NewPortMappingDescription>`)
							} else {
								testSOAPFault(w, 714)
							}
						case "AddPortMapping":
							if a.Internal != 42300 || a.Client != testLocal.String() || a.Enabled != 1 || a.Seconds == 0 || !strings.HasPrefix(a.Description, "btawg-") || a.External == 42300 || (ownedPort != 0 && a.External != ownedPort) || (mapping[a.External] != "" && mapping[a.External] != a.Description) {
								t.Errorf("unscoped or conflicting IGD add: %+v", a)
								testSOAPFault(w, 718)
								return
							}
							ownedPort = a.External
							mapping[a.External] = a.Description
							added <- a.External
							testSOAPReply(w, service, action, "")
						case "DeletePortMapping":
							deleted <- a.External
							delete(mapping, a.External)
							testSOAPReply(w, service, action, "")
						default:
							t.Errorf("unexpected action %q", action)
							w.WriteHeader(http.StatusBadRequest)
						}
					}))
					t.Cleanup(server.Close)
					conn, packets := testGateway(t)
					ssdp, discovery := testGateway(t)
					cancel, reports, done := startTestMapping(t, router{source: testLocal, gateway: testLocal, natPort: conn.LocalAddr().(*net.UDPAddr).AddrPort().Port(), ssdp: ssdp.LocalAddr().(*net.UDPAddr).AddrPort()}, 42300)
					rejectNAT(t, conn, packets)
					p := receive(t, discovery)
					if !strings.HasPrefix(string(p.data), "M-SEARCH * HTTP/1.1\r\n") {
						t.Fatalf("not SSDP discovery: %q", p.data)
					}
					sendLocation(t, ssdp, p, server.URL+"/descriptions/igd.xml")
					port := receive(t, added)
					checkReport(t, reports, "8.8.8.8:"+strconv.Itoa(int(port)))
					if renewedPort := receive(t, added); renewedPort != port {
						t.Fatalf("renewed port %d, want %d", renewedPort, port)
					}
					if replaced {
						mu.Lock()
						mapping[port] = "another owner's mapping"
						mu.Unlock()
					}
					cancel()
					checkReport(t, reports, "")
					if err := receive(t, done); err != nil {
						t.Fatal(err)
					}
					if replaced {
						select {
						case got := <-deleted:
							t.Fatalf("deleted foreign mapping %d", got)
						default:
						}
					} else if got := receive(t, deleted); got != port {
						t.Fatalf("deleted port %d, want %d", got, port)
					}
					mu.Lock()
					defer mu.Unlock()
					if mapping[42300] != "manual mapping" || replaced && mapping[port] != "another owner's mapping" {
						t.Fatalf("foreign mapping altered: %v", mapping)
					}
				})
			}
		})
	}
}

func TestIGDOnlyPermanentLeases(t *testing.T) {
	const service = "urn:schemas-upnp-org:service:WANIPConnection:1"
	for _, tc := range []struct {
		name                      string
		allow, replace, lostReply bool
	}{
		{name: "default rejects"},
		{name: "opted in", allow: true},
		{name: "foreign replacement", allow: true, replace: true},
		{name: "lost add reply", allow: true, lostReply: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var mu sync.Mutex
			var description string
			finiteRejected := make(chan struct{}, 1)
			nat, packets := testGateway(t)
			ssdp, discovery := testGateway(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method == http.MethodGet {
					fmt.Fprint(w, testDescription(service, "/control"))
					return
				}
				action := strings.TrimPrefix(strings.Trim(req.Header.Get("SOAPAction"), `"`), service+"#")
				mu.Lock()
				defer mu.Unlock()
				switch action {
				case "GetExternalIPAddress":
					testSOAPReply(w, service, action, `<NewExternalIPAddress>8.8.4.4</NewExternalIPAddress>`)
				case "GetSpecificPortMappingEntry":
					if description == "" {
						testSOAPFault(w, 714)
						return
					}
					testSOAPReply(w, service, action, `<NewInternalPort>42301</NewInternalPort><NewInternalClient>127.0.0.1</NewInternalClient><NewEnabled>1</NewEnabled><NewLeaseDuration>0</NewLeaseDuration><NewPortMappingDescription>`+description+`</NewPortMappingDescription>`)
				case "AddPortMapping":
					var envelope struct {
						Body struct {
							Add struct {
								Description string `xml:"NewPortMappingDescription"`
								Seconds     uint32 `xml:"NewLeaseDuration"`
							} `xml:"AddPortMapping"`
						}
					}
					if err := xml.NewDecoder(req.Body).Decode(&envelope); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if envelope.Body.Add.Seconds != 0 {
						testSOAPFault(w, 725)
						select {
						case finiteRejected <- struct{}{}:
						default:
						}
						return
					}
					if !tc.allow || description != "" {
						t.Error("unexpected permanent AddPortMapping")
						testSOAPFault(w, 718)
						return
					}
					description = envelope.Body.Add.Description
					if tc.lostReply {
						w.WriteHeader(http.StatusBadGateway)
						return
					}
					testSOAPReply(w, service, action, "")
				case "DeletePortMapping":
					description = ""
					testSOAPReply(w, service, action, "")
				default:
					t.Errorf("unexpected SOAP action %q", action)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer server.Close()
			r := router{source: testLocal, gateway: testLocal, natPort: nat.LocalAddr().(*net.UDPAddr).AddrPort().Port(), ssdp: ssdp.LocalAddr().(*net.UDPAddr).AddrPort()}
			r.allowPermanentUPnP = tc.allow
			cancel, reports, done := startTestMapping(t, r, 42301)
			defer cancel()
			rejectNAT(t, nat, packets)
			sendLocation(t, ssdp, receive(t, discovery), server.URL+"/igd.xml")
			receive(t, finiteRejected)
			if tc.allow {
				checkReport(t, reports, "8.8.4.4:42301")
			}
			if tc.replace {
				mu.Lock()
				description = "replacement"
				mu.Unlock()
			}
			cancel()
			if tc.allow {
				checkReport(t, reports, "")
			}
			if err := receive(t, done); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			want := ""
			if tc.replace {
				want = "replacement"
			}
			if description != want {
				t.Fatalf("mapping left on router: %q, want %q", description, want)
			}
		})
	}
}

func TestIGDRejectsOffGatewayAndRedirectsAndBoundsBodies(t *testing.T) {
	var unwanted atomic.Int32
	var requested = make(chan string, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested <- r.URL.Path
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/unexpected", http.StatusFound)
		case "/huge":
			fmt.Fprint(w, strings.Repeat(" ", 300<<10)+testDescription("urn:schemas-upnp-org:service:WANIPConnection:2", "/unexpected"))
		case "/foreign-control":
			fmt.Fprint(w, testDescription("urn:schemas-upnp-org:service:WANIPConnection:2", "http://localhost:12345/unexpected"))
		default:
			unwanted.Add(1)
		}
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, packets := testGateway(t)
	r := router{source: testLocal, gateway: testLocal, ssdp: conn.LocalAddr().(*net.UDPAddr).AddrPort()}
	done := make(chan error, 1)
	go func() {
		_, err := r.discoverIGD(ctx)
		done <- err
	}()
	p := receive(t, packets)
	spoof, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { spoof.Close() })
	sendLocation(t, spoof, p, server.URL+"/unexpected")
	sendLocation(t, conn, p, strings.Replace(server.URL, "127.0.0.1", "localhost", 1)+"/unexpected")
	for _, path := range []string{"/redirect", "/huge", "/foreign-control"} {
		sendLocation(t, conn, p, server.URL+path)
		if got := receive(t, requested); got != path {
			t.Fatalf("description fetched wrong endpoint: %q, want %q", got, path)
		}
	}
	if err := receive(t, done); err == nil || unwanted.Load() != 0 {
		t.Fatalf("unsafe IGD discovery: error %v, unwanted requests %d", err, unwanted.Load())
	}
}
