package main

import(
 "crypto/rand"
 "encoding/binary"
 "fmt"
 "io"
 "net"
 "sync"
)

// extBlockSize is the fixed data region after the uint16 length prefix in a
// private extension message, kept high-entropy with random padding.
const extBlockSize=2048
const extDataID=1

// extHandshakeMsg is a proper BEP 10 extension handshake: message id 20,
// extended id 0, bencoded {"m":{"btawg":1}} with no padding.
func extHandshakeMsg()[]byte{
 p:=[]byte("d1:md5:btawgi1ee")
 b:=make([]byte,6+len(p));binary.BigEndian.PutUint32(b,uint32(2+len(p)));b[4]=20;b[5]=0;copy(b[6:],p);return b
}

type extCarrier struct{
 c net.Conn
 writeMu sync.Mutex
 received chan []byte
 done chan struct{}
 once sync.Once
 wg sync.WaitGroup
 stats *carrierStats
}
func extMessage(id byte,p []byte)([]byte,error){
 // Payload: uint16 length + AWG datagram + random padding to extBlockSize.
 d:=make([]byte,2+extBlockSize);if len(p)>extBlockSize{return nil,fmt.Errorf("AWG datagram too large: %d",len(p))}
 binary.BigEndian.PutUint16(d[:2],uint16(len(p)));copy(d[2:],p);if _,e:=rand.Read(d[2+len(p):]);e!=nil{return nil,e}
 b:=make([]byte,6+len(d));binary.BigEndian.PutUint32(b,uint32(2+len(d)));b[4]=20;b[5]=id;copy(b[6:],d);return b,nil
}
func newExtCarrier(c net.Conn,stats *carrierStats)(transport,error){
 if e:=btHandshake(c);e!=nil{return nil,e}
 hb:=extHandshakeMsg()
 if e:=fullWrite(c,hb);e!=nil{return nil,e}
 // Read the peer's extension handshake and ignore its body.
 var lenBuf [4]byte;if _,e:=io.ReadFull(c,lenBuf[:]);e!=nil{return nil,e};n:=int(binary.BigEndian.Uint32(lenBuf[:]));if n==0||n>4098{return nil,fmt.Errorf("bad ext handshake length")}
 h:=make([]byte,n);if _,e:=io.ReadFull(c,h);e!=nil{return nil,e}
 if n<2||h[0]!=20||h[1]!=0{return nil,fmt.Errorf("bad ext handshake")}
 stats.Handshakes.Add(1)
 x:=&extCarrier{c:c,received:make(chan []byte,256),done:make(chan struct{}),stats:stats}
 x.wg.Add(1);go func(){defer x.wg.Done();x.readLoop()}()
 return x,nil
}
func newExtPair(a,b net.Conn,stats *carrierStats)(transport,transport){
 type answer struct{t transport;e error};ch:=make(chan answer,1)
 go func(){t,e:=newExtCarrier(a,stats);ch<-answer{t,e}}()
 bt,e:=newExtCarrier(b,stats);must(e);at:=<-ch;must(at.e);return at.t,bt
}
func(x *extCarrier)send(p []byte)error{
 b,e:=extMessage(extDataID,p);if e!=nil{return e}
 x.writeMu.Lock();defer x.writeMu.Unlock();if e:=fullWrite(x.c,b);e!=nil{return e};x.stats.Pieces.Add(1);x.stats.WireBytes.Add(int64(len(b)));return nil
}
func(x *extCarrier)readLoop(){
 defer x.close()
 for{
  var lenBuf [4]byte;if _,e:=io.ReadFull(x.c,lenBuf[:]);e!=nil{return};n:=int(binary.BigEndian.Uint32(lenBuf[:]));if n==0{continue};if n>4+extBlockSize{x.stats.Invalid.Add(1);return}
  b:=make([]byte,n);if _,e:=io.ReadFull(x.c,b);e!=nil{return}
  if n<2||b[0]!=20{x.stats.Invalid.Add(1);return}
  switch b[1]{
  case 0:continue // re-handshake, ignored
  case extDataID:
   if n<4{x.stats.Invalid.Add(1);return};size:=int(binary.BigEndian.Uint16(b[2:4]));if size==0||2+size>n{x.stats.Invalid.Add(1);return}
   d:=append([]byte(nil),b[4:4+size]...)
   select{case x.received<-d:case<-x.done:return}
  default:x.stats.Invalid.Add(1);return
  }
 }
}
func(x *extCarrier)close(){x.once.Do(func(){close(x.done);x.c.Close()})}
func(x *extCarrier)wait(){x.close();x.wg.Wait()}
func(x *extCarrier)recv()<-chan []byte{return x.received}
func(x *extCarrier)doneCh()<-chan struct{}{return x.done}
