package main

import (
 "crypto/rand"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "net"
 "net/netip"
 "os"
 "sort"
 "sync"
 "time"
 "github.com/amnezia-vpn/amneziawg-go/v3/conn"
 "github.com/amnezia-vpn/amneziawg-go/v3/device"
 "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
 "golang.org/x/crypto/curve25519"
)

func must(e error){if e!=nil{panic(e)}}
func key()([]byte,[]byte){b:=make([]byte,32);_,e:=rand.Read(b);must(e);p,e:=curve25519.X25519(b,curve25519.Basepoint);must(e);return b,p}
func port()int{c,e:=net.ListenPacket("udp4","127.0.0.1:0");must(e);p:=c.LocalAddr().(*net.UDPAddr).Port;c.Close();return p}
const profile="jc=4\njmin=40\njmax=100\ns1=32\ns2=32\ns3=32\ns4=32\nh1=101\nh2=102\nh3=103\nh4=104\n"
type udp interface{net.PacketConn;io.Writer}
type observation struct{Mode string;Repeat,Sent,Received,Missing,Bad int;P50,P95,P99,Max,FirstEchoMS float64;RTT []float64 `json:"rtt_ms"`}
func measure(mode string,repeat int,c udp,s net.PacketConn)observation{
 var wg sync.WaitGroup;wg.Add(1)
 go func(){defer wg.Done();b:=make([]byte,2048);for{n,a,e:=s.ReadFrom(b);if e!=nil{return};_,e=s.WriteTo(b[:n],a);if e!=nil{return}}}()
 defer func(){c.Close();s.Close();wg.Wait()}()
 r:=observation{Mode:mode,Repeat:repeat}
 var b [256]byte;buf:=make([]byte,2048)
 t:=time.Now();c.SetDeadline(t.Add(5*time.Second));_,e:=c.Write(b[:]);must(e);_,_,e=c.ReadFrom(buf);must(e);r.FirstEchoMS=float64(time.Since(t))/1e6
 // Sequential warmup is excluded; the measured stream remains open-loop.
 for range 50{_,e=c.Write(b[:]);must(e);_,_,e=c.ReadFrom(buf);must(e)}
 const count=1000
 start:=time.Now();c.SetDeadline(start.Add(13*time.Second))
 done:=make(chan struct{});var mu sync.Mutex;seen:=make(map[uint64]bool)
 go func(){defer close(done);p:=make([]byte,2048);for{n,_,e:=c.ReadFrom(p);if e!=nil{return};now:=time.Since(start);mu.Lock();if n!=256{r.Bad++;mu.Unlock();continue};seq:=binary.BigEndian.Uint64(p);stamp:=binary.BigEndian.Uint64(p[8:]);if seq>=count||stamp>uint64(now){r.Bad++;mu.Unlock();continue};if !seen[seq]{seen[seq]=true;r.RTT=append(r.RTT,float64(now-time.Duration(stamp))/1e6)};received:=len(r.RTT);mu.Unlock();if received==count{return}}}()
 tick:=time.NewTicker(10*time.Millisecond)
 for i:=range count{<-tick.C;binary.BigEndian.PutUint64(b[:],uint64(i));binary.BigEndian.PutUint64(b[8:],uint64(time.Since(start)));_,e=c.Write(b[:]);must(e);r.Sent++}
 tick.Stop();select{case<-done:case<-time.After(2*time.Second):c.SetReadDeadline(time.Now());<-done}
 mu.Lock();defer mu.Unlock();sort.Float64s(r.RTT);r.Received=len(r.RTT);r.Missing=r.Sent-r.Received
 q:=func(p float64)float64{if len(r.RTT)==0{return -1};return r.RTT[int(float64(len(r.RTT)-1)*p)]};r.P50=q(.5);r.P95=q(.95);r.P99=q(.99);r.Max=q(1)
 return r
}
func raw(repeat int)observation{s,e:=net.ListenPacket("udp4","127.0.0.1:0");must(e);c,e:=net.DialUDP("udp4",nil,s.LocalAddr().(*net.UDPAddr));must(e);return measure("udp-loopback",repeat,c,s)}
func awg(repeat int)observation{
 ca:=netip.MustParseAddr("10.77.0.1");sa:=netip.MustParseAddr("10.77.0.2")
 ct,cn,e:=netstack.CreateNetTUN([]netip.Addr{ca},nil,1420);must(e)
 st,sn,e:=netstack.CreateNetTUN([]netip.Addr{sa},nil,1420);must(e)
 cd:=device.NewDevice(ct,conn.NewDefaultBind(),device.NewLogger(device.LogLevelError,"client: "));sd:=device.NewDevice(st,conn.NewDefaultBind(),device.NewLogger(device.LogLevelError,"server: "));defer cd.Close();defer sd.Close()
 ck,cp:=key();sk,sp:=key();cport,sport:=port(),port();for sport==cport{sport=port()}
 conf:=func(priv,pub []byte,listen,remote int,ip netip.Addr)string{return fmt.Sprintf("private_key=%s\nlisten_port=%d\n%sreplace_peers=true\npublic_key=%s\nallowed_ip=%s/32\nendpoint=127.0.0.1:%d\n",hex.EncodeToString(priv),listen,profile,hex.EncodeToString(pub),ip,remote)}
 must(sd.IpcSet(conf(sk,cp,sport,cport,ca)));must(cd.IpcSet(conf(ck,sp,cport,sport,sa)));must(sd.Up());must(cd.Up())
 s,e:=sn.ListenUDPAddrPort(netip.AddrPortFrom(sa,9000));must(e)
 c,e:=cn.DialUDPAddrPort(netip.AddrPortFrom(ca,0),netip.AddrPortFrom(sa,9000));must(e)
 r:=measure("awg-userspace-loopback",repeat,c,s)
 // Require authenticated packets and an established handshake, not a plaintext echo.
 for _,d:=range []*device.Device{cd,sd}{state,e:=d.IpcGet();must(e);if !hasHandshake(state){panic("AWG handshake not established")}}
 return r
}
func hasHandshake(s string)bool{for _,line:=range splitLines(s){var n int64;if _,e:=fmt.Sscanf(line,"last_handshake_time_sec=%d",&n);e==nil&&n>0{return true}};return false}
func splitLines(s string)[]string{var lines []string;start:=0;for i:=range len(s){if s[i]=='\n'{lines=append(lines,s[start:i]);start=i+1}};return lines}
func main(){fmt.Fprintln(os.Stderr,"Official amneziawg-go/v3 v3.1.20261116; actual default UDP Bind; gVisor netstack TUN; IPv4 localhost; payload=256 interval=10ms measured=1000 warmup=50; no induced delay/loss; profile:",profile);enc:=json.NewEncoder(os.Stdout);for repeat:=range 3{for _,f:=range []func(int)observation{raw,awg}{r:=f(repeat);must(enc.Encode(r));fmt.Fprintf(os.Stderr,"%s repeat=%d delivery=%d/%d p50=%.3f p95=%.3f p99=%.3f max=%.3f first=%.3f\n",r.Mode,repeat,r.Received,r.Sent,r.P50,r.P95,r.P99,r.Max,r.FirstEchoMS)}}}
