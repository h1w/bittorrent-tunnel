package main

import(
 "crypto/rand"
 "encoding/binary"
 "fmt"
 "io"
 "net"
 "sync"
 "time"
)

// webBlockSize is the fixed record size in the webseed response body: a uint16
// length, the AWG datagram, and random padding filling the rest.
const webBlockSize=2048

const webResponseHead="HTTP/1.1 206 Partial Content\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes 0-10485759/10485760\r\nContent-Length: 10485760\r\n\r\n"
const webRequestHead="GET /btawg HTTP/1.1\r\nHost: webseed\r\nRange: bytes=0-10485759\r\n\r\n"

type webCarrier struct{
 out net.Conn // server role: we stream our outgoing datagrams here
 in net.Conn  // client role: we read the peer's outgoing datagrams here
 outq chan []byte
 received chan []byte
 done chan struct{}
 once sync.Once
 wg sync.WaitGroup
 stats *carrierStats
}
func readHTTPHead(c net.Conn)([]byte,error){
 buf:=make([]byte,0,256);one:=make([]byte,1)
 for len(buf)<4096{if _,e:=io.ReadFull(c,one);e!=nil{return nil,e};buf=append(buf,one[0]);if len(buf)>=4&&string(buf[len(buf)-4:])=="\r\n\r\n"{return buf,nil}}
 return nil,fmt.Errorf("HTTP head too long")
}
func newWebCarrier(out,in net.Conn,stats *carrierStats)(transport,error){
 x:=&webCarrier{out:out,in:in,outq:make(chan []byte,64),received:make(chan []byte,256),done:make(chan struct{}),stats:stats}
 x.wg.Add(2)
 go func(){defer x.wg.Done();x.serverLoop()}()
 go func(){defer x.wg.Done();x.clientLoop()}()
 return x,nil
}
func newWebPair(aServer,aClient,bServer,bClient net.Conn,stats *carrierStats)(transport,transport){
 type answer struct{t transport;e error};ch:=make(chan answer,1)
 go func(){t,e:=newWebCarrier(aServer,aClient,stats);ch<-answer{t,e}}()
 bt,e:=newWebCarrier(bServer,bClient,stats);must(e);at:=<-ch;must(at.e);return at.t,bt
}
func(x *webCarrier)serverLoop(){
 defer x.close()
 if _,e:=readHTTPHead(x.out);e!=nil{return}
 if e:=fullWrite(x.out,[]byte(webResponseHead));e!=nil{return}
 for{select{case p:=<-x.outq:if e:=x.writeRecord(p);e!=nil{return};case<-x.done:return}}
}
func(x *webCarrier)clientLoop(){
 defer x.close()
 if e:=fullWrite(x.in,[]byte(webRequestHead));e!=nil{return}
 if _,e:=readHTTPHead(x.in);e!=nil{return}
 for{
  var lb [2]byte;if _,e:=io.ReadFull(x.in,lb[:]);e!=nil{return};n:=int(binary.BigEndian.Uint16(lb[:]));if n==0||n>webBlockSize-2{x.stats.Invalid.Add(1);return}
  rec:=make([]byte,webBlockSize-2);if _,e:=io.ReadFull(x.in,rec);e!=nil{return}
  d:=append([]byte(nil),rec[:n]...);x.stats.Pieces.Add(1)
  select{case x.received<-d:case<-x.done:return}
 }
}
func(x *webCarrier)writeRecord(p []byte)error{
 if len(p)>webBlockSize-2{return fmt.Errorf("AWG datagram too large: %d",len(p))}
 rec:=make([]byte,webBlockSize);binary.BigEndian.PutUint16(rec[:2],uint16(len(p)));copy(rec[2:],p);if _,e:=rand.Read(rec[2+len(p):]);e!=nil{return e}
 if e:=fullWrite(x.out,rec);e!=nil{return e};x.stats.WireBytes.Add(int64(len(rec)));return nil
}
func(x *webCarrier)send(p []byte)error{select{case x.outq<-p:return nil;case<-x.done:return net.ErrClosed}}
func(x *webCarrier)close(){x.once.Do(func(){close(x.done);x.out.Close();x.in.Close()})}
func(x *webCarrier)wait(){x.close();x.wg.Wait()}
func(x *webCarrier)recv()<-chan []byte{return x.received}
func(x *webCarrier)doneCh()<-chan struct{}{return x.done}

// webseedLane builds two raw TCP connections per lane (A server on one, B
// server on the other) and returns the two peers' carriers. TCP-only; the
// one-way delay is applied by wrapping each raw connection with wrapDelay.
func webseedLane(stats *carrierStats, delay time.Duration)(transport,transport){
 ln1,e:=net.Listen("tcp4","127.0.0.1:0");must(e)
 c1:=make(chan net.Conn,1);go func(){c,e:=ln1.Accept();must(e);c1<-c}()
 bConn1,e:=net.Dial("tcp4",ln1.Addr().String());must(e);aConn1:=<-c1;ln1.Close()
 ln2,e:=net.Listen("tcp4","127.0.0.1:0");must(e)
 c2:=make(chan net.Conn,1);go func(){c,e:=ln2.Accept();must(e);c2<-c}()
 aConn2,e:=net.Dial("tcp4",ln2.Addr().String());must(e);bConn2:=<-c2;ln2.Close()
 for _,c:=range []net.Conn{aConn1,bConn1,aConn2,bConn2}{c.(*net.TCPConn).SetNoDelay(true);c.SetDeadline(time.Now().Add(40*time.Second))}
 aConn1=wrapDelay(aConn1,delay);bConn1=wrapDelay(bConn1,delay);aConn2=wrapDelay(aConn2,delay);bConn2=wrapDelay(bConn2,delay)
 return newWebPair(aConn1,aConn2,bConn2,bConn1,stats)
}
