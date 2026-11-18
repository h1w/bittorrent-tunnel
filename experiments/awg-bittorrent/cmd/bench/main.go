package main

import(
 "crypto/rand"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "net"
 "net/netip"
 "os"
 "path/filepath"
 "sort"
 "sync"
 "time"
 utp "github.com/anacrolix/go-utp"
 "github.com/anacrolix/go-utp/purego"
 "github.com/amnezia-vpn/amneziawg-go/v3/device"
 "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
 "golang.org/x/crypto/curve25519"
)
func must(e error){if e!=nil{panic(e)}}
func key()([]byte,[]byte){b:=make([]byte,32);_,e:=rand.Read(b);must(e);p,e:=curve25519.X25519(b,curve25519.Basepoint);must(e);return b,p}
const profile="jc=4\njmin=40\njmax=100\ns1=32\ns2=32\ns3=32\ns4=32\nh1=101\nh2=102\nh3=103\nh4=104\n"
type variant struct{Name,Impl string;NoNagle bool;Copies,Lanes int}
var variants=[]variant{{"awg-direct","direct",false,1,1},{"awg-bt-tcp","tcp",false,1,1},{"awg-bt-libutp","lib",false,1,1},{"awg-bt-go-default","go",false,1,1},{"awg-bt-go-nn","go",true,1,1},{"awg-bt-go-nn-dup","go",true,2,1},{"awg-bt-go-nn-2lanes","go",true,1,2},{"awg-bt-ext-utp","ext-utp",true,1,1},{"awg-bt-ext-tcp","ext-tcp",false,1,1},{"awg-bt-webseed","webseed",false,1,1}}
func usesUTP(impl string)bool{return impl=="lib"||impl=="go"||impl=="ext-utp"}
type observation struct{Mode,Channel string;Repeat,Sent,Received,Missing,Bad,Over100,Reordered int;P50,P95,P99,Max,FirstEchoMS float64;Handshakes,Requests,Pieces,Invalid,BTBytes,Packets,OuterBytes,Drops int64;RTT []float64 `json:"rtt_ms"`}
type udp interface{net.PacketConn;io.Writer}
func measure(r observation,c udp,s net.PacketConn,count int)observation{
 var wg sync.WaitGroup;wg.Add(1);go func(){defer wg.Done();p:=make([]byte,2048);for{n,a,e:=s.ReadFrom(p);if e!=nil{return};if _,e=s.WriteTo(p[:n],a);e!=nil{return}}}();defer func(){c.Close();s.Close();wg.Wait()}()
 var b [256]byte;buf:=make([]byte,2048);t:=time.Now();c.SetDeadline(t.Add(8*time.Second));_,e:=c.Write(b[:]);must(e);_,_,e=c.ReadFrom(buf);must(e);r.FirstEchoMS=float64(time.Since(t))/1e6
 for range 50{_,e=c.Write(b[:]);must(e);_,_,e=c.ReadFrom(buf);must(e)}
 start:=time.Now();c.SetDeadline(start.Add(time.Duration(count)*10*time.Millisecond+4*time.Second));done:=make(chan struct{});seen:=make(map[uint64]bool)
 go func(){defer close(done);p:=make([]byte,2048);var last uint64;for{n,_,e:=c.ReadFrom(p);if e!=nil{return};now:=time.Since(start);if n!=256{r.Bad++;continue};seq:=binary.BigEndian.Uint64(p);stamp:=binary.BigEndian.Uint64(p[8:]);if seq>=uint64(count)||stamp>uint64(now){r.Bad++;continue};if !seen[seq]{if len(seen)>0&&seq<last{r.Reordered++};last=seq;seen[seq]=true;d:=float64(now-time.Duration(stamp))/1e6;r.RTT=append(r.RTT,d);if d>100{r.Over100++}};if len(seen)==count{return}}}()
 tick:=time.NewTicker(10*time.Millisecond);for i:=range count{<-tick.C;binary.BigEndian.PutUint64(b[:],uint64(i));binary.BigEndian.PutUint64(b[8:],uint64(time.Since(start)));_,e=c.Write(b[:]);must(e)};tick.Stop();r.Sent=count
 select{case<-done:case<-time.After(2*time.Second):c.SetReadDeadline(time.Now());<-done}
 sort.Float64s(r.RTT);r.Received=len(r.RTT);r.Missing=r.Sent-r.Received;q:=func(p float64)float64{if len(r.RTT)==0{return -1};return r.RTT[int(float64(len(r.RTT)-1)*p)]};r.P50=q(.5);r.P95=q(.95);r.P99=q(.99);r.Max=q(1);return r
}
func carrierPair(a,b net.Conn,stats *carrierStats)(*carrier,*carrier){
 type answer struct{c *carrier;e error};ch:=make(chan answer,1);go func(){c,e:=newCarrier(a,stats);ch<-answer{c,e}}();bc,e:=newCarrier(b,stats);must(e);ac:=<-ch;must(ac.e)
 done:=make(chan struct{});go func(){ac.c.start(false);close(done)}();bc.start(true);<-done;return ac.c,bc
}
func run(v variant,s scenario,repeat,count int)observation{
 purego.MatrixDisableNagle=v.NoNagle;stats:=&carrierStats{}
 na,nb:=newNetwork(s,uint64(71+repeat)),newNetwork(s,uint64(91+repeat));a,b:=endpoint(na,v.Copies),endpoint(nb,v.Copies)
 cb,sb:=&benchBind{},&benchBind{};var transportClose func()
 if v.Impl=="direct"{cb.packet=a;sb.packet=b;cb.remote=endpointID{netip.MustParseAddrPort(b.LocalAddr().String())};sb.remote=endpointID{netip.MustParseAddrPort(a.LocalAddr().String())};transportClose=func(){a.Close();b.Close()}}else{
  cb.remote=endpointID{netip.MustParseAddrPort("127.0.0.1:31002")};sb.remote=endpointID{netip.MustParseAddrPort("127.0.0.1:31001")}
  var sa,ss utp.Socket
  if usesUTP(v.Impl){impl:=utp.PureGo;if v.Impl=="lib"{impl=utp.LibUtp};opts:=[]utp.Option{utp.WithTargetDelay(5*time.Millisecond),utp.WithBufferSizes(65536,65536)};var e error;sa,e=impl.NewSocket(a,opts...);must(e);ss,e=impl.NewSocket(b,opts...);must(e)}
  for range v.Lanes{
   if v.Impl=="webseed"{xc,yc:=webseedLane(stats,s.Delay);cb.carriers=append(cb.carriers,xc);sb.carriers=append(sb.carriers,yc);continue}
   var x,y net.Conn
   if usesUTP(v.Impl){accepted:=make(chan net.Conn,1);go func(){c,e:=ss.Accept();must(e);accepted<-c}();var e error;x,e=sa.DialTimeout(b.LocalAddr().String(),5*time.Second);must(e);y=<-accepted
   }else{ln,e:=net.Listen("tcp4","127.0.0.1:0");must(e);accepted:=make(chan net.Conn,1);go func(){c,e:=ln.Accept();must(e);accepted<-c}();x,e=net.Dial("tcp4",ln.Addr().String());must(e);y=<-accepted;ln.Close();x.(*net.TCPConn).SetNoDelay(true);y.(*net.TCPConn).SetNoDelay(true);x=wrapDelay(x,s.Delay);y=wrapDelay(y,s.Delay)}
   x.SetDeadline(time.Now().Add(40*time.Second));y.SetDeadline(time.Now().Add(40*time.Second))
   if v.Impl=="ext-utp"||v.Impl=="ext-tcp"{xc,yc:=newExtPair(x,y,stats);cb.carriers=append(cb.carriers,xc);sb.carriers=append(sb.carriers,yc)}else{xc,yc:=carrierPair(x,y,stats);cb.carriers=append(cb.carriers,xc);sb.carriers=append(sb.carriers,yc)}
  }
  transportClose=func(){for _,c:=range cb.carriers{c.wait()};for _,c:=range sb.carriers{c.wait()};if sa!=nil{sa.Close();ss.Close()}else{a.Close();b.Close()}}
 }
 defer transportClose()
 ca:=netip.MustParseAddr("10.78.0.1");server:=netip.MustParseAddr("10.78.0.2");ct,cn,e:=netstack.CreateNetTUN([]netip.Addr{ca},nil,1420);must(e);st,sn,e:=netstack.CreateNetTUN([]netip.Addr{server},nil,1420);must(e)
 cd:=device.NewDevice(ct,cb,device.NewLogger(device.LogLevelError,"client: "));sd:=device.NewDevice(st,sb,device.NewLogger(device.LogLevelError,"server: "));defer cd.Close();defer sd.Close();ck,cp:=key();sk,sp:=key()
 conf:=func(priv,pub []byte,ep endpointID,ip netip.Addr)string{return fmt.Sprintf("private_key=%s\n%sreplace_peers=true\npublic_key=%s\nallowed_ip=%s/32\nendpoint=%s\n",hex.EncodeToString(priv),profile,hex.EncodeToString(pub),ip,ep.DstToString())}
 must(sd.IpcSet(conf(sk,cp,sb.remote,ca)));must(cd.IpcSet(conf(ck,sp,cb.remote,server)));must(sd.Up());must(cd.Up());phase:=time.Now();na.activate(phase);nb.activate(phase)
 echo,e:=sn.ListenUDPAddrPort(netip.AddrPortFrom(server,9000));must(e);client,e:=cn.DialUDPAddrPort(netip.AddrPortFrom(ca,0),netip.AddrPortFrom(server,9000));must(e)
 r:=measure(observation{Mode:v.Name,Channel:s.Name,Repeat:repeat},client,echo,count)
 for _,d:=range []*device.Device{cd,sd}{state,e:=d.IpcGet();must(e);valid:=false;for _,line:=range splitLines(state){var n int64;if _,e:=fmt.Sscanf(line,"last_handshake_time_sec=%d",&n);e==nil&&n>0{valid=true}};if !valid{panic("no authenticated AWG handshake")}}
 r.Handshakes=stats.Handshakes.Load();r.Requests=stats.Requests.Load();r.Pieces=stats.Pieces.Load();r.Invalid=stats.Invalid.Load();r.BTBytes=stats.WireBytes.Load();ws,wt:=na.snapshot(),nb.snapshot();r.Packets=ws.Attempts+wt.Attempts;r.OuterBytes=ws.Bytes+wt.Bytes;r.Drops=ws.Drops+wt.Drops;return r
}
func splitLines(s string)[]string{var lines []string;start:=0;for i:=range len(s){if s[i]=='\n'{lines=append(lines,s[start:i]);start=i+1}};return lines}
func main(){count:=flag.Int("count",400,"measured messages");repeats:=flag.Int("repeats",3,"repetitions");only:=flag.String("only","","one mode");capture:=flag.String("capture","","write outer-traffic pcaps into this dir");flag.Parse();enc:=json.NewEncoder(os.Stdout)
 for repeat:=range *repeats{for _,s:=range []scenario{{Name:"clean40",Delay:20*time.Millisecond}}{for _,v:=range variants{if *only!=""&&v.Name!=*only{continue};if *capture!=""{must(startCapture(filepath.Join(*capture,fmt.Sprintf("%s-s%d.pcap",v.Name,repeat))))};r:=run(v,s,repeat,*count);if *capture!=""{stopCapture()};must(enc.Encode(r));fmt.Fprintf(os.Stderr,"%s %s seed=%d delivery=%d/%d p95=%.3f max=%.3f bt_handshakes=%d pieces=%d invalid=%d\n",v.Name,s.Name,repeat,r.Received,r.Sent,r.P95,r.Max,r.Handshakes,r.Pieces,r.Invalid)}}}
}
