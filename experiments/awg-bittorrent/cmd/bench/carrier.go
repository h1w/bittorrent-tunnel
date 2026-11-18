package main

import(
 "bytes"
 "crypto/rand"
 "encoding/binary"
 "fmt"
 "io"
 "net"
 "sync"
 "sync/atomic"
)

// This is a wire-format experiment, NOT a valid immutable-file torrent.
// AWG ciphertext replaces file blocks. File hashes therefore do not validate.
const blockSize=2048
const requestWindow=32
const totalPieces=65536
var experimentHash=[20]byte{0x42,0x54,0x41,0x57,0x47,1}
type request struct{Index,Offset,Length uint32}
type carrierStats struct{Handshakes,Requests,Pieces,Invalid,WireBytes atomic.Int64}
type carrier struct{
 c net.Conn
 writeMu sync.Mutex
 requests chan request
 received chan []byte
 done chan struct{}
 once sync.Once
 wg sync.WaitGroup
 stats *carrierStats
 pending map[uint32]bool
 next uint32
}
func fullWrite(c net.Conn,b []byte)error{if tc,ok:=c.(*net.TCPConn);ok{captureTCP(tc,b)};for len(b)>0{n,e:=c.Write(b);if e!=nil{return e};if n==0{return io.ErrShortWrite};b=b[n:]};return nil}
func (x *carrier)message(id byte,p []byte)error{
 b:=make([]byte,5+len(p));binary.BigEndian.PutUint32(b,uint32(len(p)+1));b[4]=id;copy(b[5:],p)
 x.writeMu.Lock();defer x.writeMu.Unlock();e:=fullWrite(x.c,b);if e==nil{x.stats.WireBytes.Add(int64(len(b)))};return e
}
func newCarrier(c net.Conn,stats *carrierStats)(*carrier,error){
 x:=&carrier{c:c,requests:make(chan request,requestWindow),received:make(chan []byte,256),done:make(chan struct{}),stats:stats,pending:make(map[uint32]bool)}
 h:=make([]byte,68);h[0]=19;copy(h[1:],"BitTorrent protocol");copy(h[28:],experimentHash[:]);_,e:=rand.Read(h[48:]);if e!=nil{return nil,e}
 sendErr:=make(chan error,1);go func(){sendErr<-fullWrite(c,h)}()
 got:=make([]byte,68);_,e=io.ReadFull(c,got);if e!=nil{c.Close();<-sendErr;return nil,e};if e=<-sendErr;e!=nil{return nil,e}
 if got[0]!=19||string(got[1:20])!="BitTorrent protocol"||!bytes.Equal(got[28:48],experimentHash[:]){return nil,fmt.Errorf("invalid BT handshake")}
 stats.Handshakes.Add(1)
 // Each endpoint advertises one half of a virtual file. Endpoint polarity
 // is supplied by caller via the peer-specific index range in start().
 return x,nil
}
func(x *carrier)start(ownOdd bool){
 own:=make([]byte,totalPieces/8)
 for i:=range totalPieces{if (i%2==1)==ownOdd{own[i/8]|=1<<uint(7-i%8)}}
 x.next=0;if !ownOdd{x.next=1}
 x.wg.Add(1);go func(){defer x.wg.Done();x.readLoop()}()
 if e:=x.message(5,own);e!=nil{x.close();return}
 if e:=x.message(2,nil);e!=nil{x.close();return}
 if e:=x.message(1,nil);e!=nil{x.close();return}
 // Initial credits are issued only after bitfield and unchoke are received.
}
func(x *carrier)issue()error{
 if x.next>=totalPieces{return fmt.Errorf("virtual piece space exhausted")}
 idx:=x.next;x.next+=2;x.pending[idx]=true
 var p [12]byte;binary.BigEndian.PutUint32(p[:],idx);binary.BigEndian.PutUint32(p[8:],blockSize)
 return x.message(6,p[:])
}
func(x *carrier)readLoop(){
 defer x.close()
 bitfield,unchoked,primed:=false,false,false
 for{
  var h [4]byte;if _,e:=io.ReadFull(x.c,h[:]);e!=nil{return};n:=int(binary.BigEndian.Uint32(h[:]));if n==0{continue};if n>16397{x.stats.Invalid.Add(1);return}
  b:=make([]byte,n);if _,e:=io.ReadFull(x.c,b);e!=nil{return}
  switch b[0]{
  case 5:if len(b)!=1+totalPieces/8{x.stats.Invalid.Add(1);return};bitfield=true
  case 1:unchoked=true
  case 2:
  case 6:
   if len(b)!=13{x.stats.Invalid.Add(1);return};r:=request{binary.BigEndian.Uint32(b[1:]),binary.BigEndian.Uint32(b[5:]),binary.BigEndian.Uint32(b[9:])}
   // Opposite parity to our requested blocks is our advertised half.
   if r.Index>=totalPieces||r.Index%2==x.next%2||r.Offset!=0||r.Length!=blockSize{x.stats.Invalid.Add(1);return}
   x.stats.Requests.Add(1);select{case x.requests<-r:case<-x.done:return}
  case 7:
   if len(b)!=1+8+blockSize{x.stats.Invalid.Add(1);return};idx:=binary.BigEndian.Uint32(b[1:]);off:=binary.BigEndian.Uint32(b[5:]);if !x.pending[idx]||off!=0{x.stats.Invalid.Add(1);return};delete(x.pending,idx)
   size:=int(binary.BigEndian.Uint16(b[9:11]));if size==0||size>blockSize-2{x.stats.Invalid.Add(1);return};p:=append([]byte(nil),b[11:11+size]...)
   x.stats.Pieces.Add(1);select{case x.received<-p:case<-x.done:return}
   // Request the next virtual piece immediately; no per-packet request RTT.
   if e:=x.issue();e!=nil{return}
  default:x.stats.Invalid.Add(1);return
  }
  if bitfield&&unchoked&&!primed{primed=true;for range requestWindow{if e:=x.issue();e!=nil{return}}}
 }
}
func(x *carrier)send(p []byte)error{
 if len(p)>blockSize-2{return fmt.Errorf("AWG datagram too large: %d",len(p))}
 var r request;select{case r=<-x.requests:case<-x.done:return net.ErrClosed}
 b:=make([]byte,8+blockSize);binary.BigEndian.PutUint32(b,r.Index);binary.BigEndian.PutUint16(b[8:],uint16(len(p)));copy(b[10:],p)
 // Fill the block tail with random bytes so each piece reads as high-entropy content.
 if _,e:=rand.Read(b[10+len(p):]);e!=nil{return e}
 return x.message(7,b)
}
func(x *carrier)close(){x.once.Do(func(){close(x.done);x.c.Close()})}
func(x *carrier)wait(){x.close();x.wg.Wait()}
func(x *carrier)recv()<-chan []byte{return x.received}
func(x *carrier)doneCh()<-chan struct{}{return x.done}

// btHandshake performs the 68-byte BitTorrent protocol handshake on a ready
// connection and returns an error if the magic, infohash, or framing is wrong.
func btHandshake(c net.Conn)error{
 h:=make([]byte,68);h[0]=19;copy(h[1:],"BitTorrent protocol");copy(h[28:],experimentHash[:]);_,e:=rand.Read(h[48:]);if e!=nil{return e}
 sendErr:=make(chan error,1);go func(){sendErr<-fullWrite(c,h)}()
 got:=make([]byte,68);_,e=io.ReadFull(c,got);if e!=nil{c.Close();<-sendErr;return e};if e=<-sendErr;e!=nil{return e}
 if got[0]!=19||string(got[1:20])!="BitTorrent protocol"||!bytes.Equal(got[28:48],experimentHash[:]){return fmt.Errorf("invalid BT handshake")}
 return nil
}
