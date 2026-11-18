package main

import(
 "encoding/binary"
 "net"
 "net/netip"
 "sync"
 "github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

type endpointID struct{addr netip.AddrPort}
func(e endpointID)ClearSrc(){}
func(e endpointID)SrcToString()string{return ""}
func(e endpointID)DstToString()string{return e.addr.String()}
func(e endpointID)DstToBytes()[]byte{a:=e.addr.Addr().As4();b:=make([]byte,6);copy(b,a[:]);binary.BigEndian.PutUint16(b[4:],e.addr.Port());return b}
func(e endpointID)DstIP()netip.Addr{return e.addr.Addr()}
func(e endpointID)SrcIP()netip.Addr{return netip.Addr{}}
// Fixed-peer experimental Bind. No plaintext AWG socket in carrier mode.
type benchBind struct{
 mu sync.Mutex
 packet *impaired
 carriers []transport
 remote endpointID
 closed chan struct{}
 once sync.Once
 turn uint64
}
func(b *benchBind)Open(port uint16)([]conn.ReceiveFunc,uint16,error){
 b.mu.Lock();defer b.mu.Unlock()
 if b.closed!=nil{return nil,0,conn.ErrBindAlreadyOpen};b.closed=make(chan struct{})
 var fns []conn.ReceiveFunc
 if b.packet!=nil{
  fns=append(fns,func(p [][]byte,sizes []int,eps []conn.Endpoint)(int,error){n,a,e:=b.packet.ReadFrom(p[0]);if e!=nil{return 0,e};ep,err:=netip.ParseAddrPort(a.String());if err!=nil{return 0,err};sizes[0]=n;eps[0]=endpointID{ep};return 1,nil})
  return fns,uint16(b.packet.LocalAddr().(*net.UDPAddr).Port),nil
 }
 for _,c:=range b.carriers{fns=append(fns,func(p [][]byte,sizes []int,eps []conn.Endpoint)(int,error){select{case d:=<-c.recv():if len(d)>len(p[0]){return 0,net.ErrClosed};sizes[0]=copy(p[0],d);eps[0]=b.remote;return 1,nil;case<-b.closed:return 0,net.ErrClosed;case<-c.doneCh():return 0,net.ErrClosed}})}
 return fns,port,nil
}
func(b *benchBind)Close()error{b.mu.Lock();opened:=b.closed!=nil;b.mu.Unlock();if !opened{return nil};b.once.Do(func(){b.mu.Lock();close(b.closed);b.mu.Unlock();if b.packet!=nil{b.packet.Close()};for _,c:=range b.carriers{c.close()}});return nil}
func(b *benchBind)SetMark(uint32)error{return nil}
func(b *benchBind)ParseEndpoint(s string)(conn.Endpoint,error){a,e:=netip.ParseAddrPort(s);return endpointID{a},e}
func(b *benchBind)BatchSize()int{return 1}
func(b *benchBind)Send(bufs [][]byte,ep conn.Endpoint)error{
 for _,p:=range bufs{
  if b.packet!=nil{a,e:=net.ResolveUDPAddr("udp4",ep.DstToString());if e!=nil{return e};if _,e=b.packet.WriteTo(p,a);e!=nil{return e};continue}
  // Lane striping is intentionally not claimed to preserve inner-flow order.
  b.mu.Lock();lane:=int(b.turn%uint64(len(b.carriers)));b.turn++;b.mu.Unlock()
  if e:=b.carriers[lane].send(p);e!=nil{return e}
 }
 return nil
}
