package main

import(
 "encoding/binary"
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "net"
 "os"
 "runtime"
 "sort"
 "sync"
 "time"
 utp "github.com/anacrolix/go-utp"
 "github.com/anacrolix/go-utp/purego"
)
type variant struct{Name,Impl string; NoNagle bool; Target time.Duration; Buffer,Lanes,Copies int}
var variants=[]variant{
 {"udp","udp",false,0,0,1,1},
 {"libutp","lib",false,100*time.Millisecond,65536,1,1},
 {"go-default","go",false,100*time.Millisecond,65536,1,1},
 {"go-nn100","go",true,100*time.Millisecond,65536,1,1},
 {"go-nn5","go",true,5*time.Millisecond,65536,1,1},
 {"go-nn1","go",true,time.Millisecond,65536,1,1},
 {"go-nn5-smallbuf","go",true,5*time.Millisecond,8192,1,1},
 {"go-nn5-4lanes","go",true,5*time.Millisecond,65536,4,1},
 {"go-nn5-dup","go",true,5*time.Millisecond,65536,1,2},
 {"go-nn5-4lanes-dup","go",true,5*time.Millisecond,65536,4,2},
}
var scenarios=[]scenario{{Name:"clean"},{Name:"loss1",Loss:.01},{Name:"burst50",Burst:true},{Name:"load2mbit",Loss:.01,Rate:2000000,Load:true}}
type result struct{
 Variant,Scenario string
 Repeat int
 Sent,Received,Missing,Over100,Bad,Reordered,WriteErrors int
 P50,P95,P99,Max,MaxFlowGap,MaxWrite float64
 Packets,WireBytes,Drops,QueueDrops int64
 Errors []string
 RTT []float64 `json:"rtt_ms"`
}
func must(e error){if e!=nil{panic(e)}}
func writeRecord(c net.Conn,p []byte)error{
 b:=make([]byte,2+len(p));binary.BigEndian.PutUint16(b,uint16(len(p)));copy(b[2:],p)
 for len(b)>0{n,e:=c.Write(b);if e!=nil{return e};if n==0{return io.ErrShortWrite};b=b[n:]}
 return nil
}
func readRecord(c net.Conn)([]byte,error){var h [2]byte;if _,e:=io.ReadFull(c,h[:]);e!=nil{return nil,e};n:=int(binary.BigEndian.Uint16(h[:]));if n<24||n>1400{return nil,fmt.Errorf("record length %d",n)};p:=make([]byte,n);_,e:=io.ReadFull(c,p);return p,e}
func percentile(v []float64,q float64)float64{if len(v)==0{return -1};return v[int(float64(len(v)-1)*q)]}
func run(v variant,s scenario,repeat,count int)result{
 r:=result{Variant:v.Name,Scenario:s.Name,Repeat:repeat}
 purego.MatrixDisableNagle=v.NoNagle
 na,nb:=newNetwork(s,uint64(100+repeat)),newNetwork(s,uint64(200+repeat))
 a,b:=endpoint(na,v.Copies),endpoint(nb,v.Copies)
 var wg sync.WaitGroup
 var mu sync.Mutex
 start:=time.Now()
 seen:=make(map[uint64]bool);lastSeq:=map[uint64]uint64{};lastTime:=map[uint64]time.Time{}
 consume:=func(p []byte){
  now:=time.Now();if len(p)<24{mu.Lock();r.Bad++;mu.Unlock();return}
  seq:=binary.BigEndian.Uint64(p);flow:=binary.BigEndian.Uint64(p[8:]);stamp:=time.Duration(binary.BigEndian.Uint64(p[16:]));sentAt:=start.Add(stamp)
  if seq>=uint64(count)||flow>=4{return}
  mu.Lock();defer mu.Unlock();if seen[seq]{return};seen[seq]=true
  if prev,ok:=lastSeq[flow];ok&&seq<prev{r.Reordered++};lastSeq[flow]=seq
  if t,ok:=lastTime[flow];ok{gap:=float64(now.Sub(t))/1e6;if gap>r.MaxFlowGap{r.MaxFlowGap=gap}};lastTime[flow]=now
  elapsed:=float64(now.Sub(sentAt))/1e6;r.RTT=append(r.RTT,elapsed);if elapsed>100{r.Over100++}
 }
 var sends []func([]byte)error
 var shutdown func()
 if v.Impl=="udp"{
  wg.Add(2)
  go func(){defer wg.Done();buf:=make([]byte,2048);for{n,addr,e:=b.ReadFrom(buf);if e!=nil{return};b.WriteTo(buf[:n],addr)}}()
  go func(){defer wg.Done();buf:=make([]byte,2048);for{n,_,e:=a.ReadFrom(buf);if e!=nil{return};consume(buf[:n])}}()
  sends=[]func([]byte)error{func(p []byte)error{_,e:=a.WriteTo(p,b.LocalAddr());return e}}
  shutdown=func(){a.Close();b.Close()}
 }else{
  impl:=utp.PureGo;if v.Impl=="lib"{impl=utp.LibUtp}
  opts:=[]utp.Option{utp.WithTargetDelay(v.Target),utp.WithBufferSizes(v.Buffer,v.Buffer)}
  sa,e:=impl.NewSocket(a,opts...);must(e);sb,e:=impl.NewSocket(b,opts...);must(e)
  var servers []net.Conn;clients:=make([]net.Conn,0,v.Lanes)
  accepted:=make(chan net.Conn,1);acceptErrors:=make(chan error,1)
  for range v.Lanes{
   go func(){c,e:=sb.Accept();if e!=nil{acceptErrors<-e}else{accepted<-c}}()
   c,e:=sa.DialTimeout(b.LocalAddr().String(),8*time.Second);must(e)
   var peer net.Conn;select{case peer=<-accepted:case e=<-acceptErrors:panic(e)}
   clients=append(clients,c);servers=append(servers,peer)
   deadline:=time.Now().Add(30*time.Second);c.SetDeadline(deadline);peer.SetDeadline(deadline)
   wg.Add(2)
   go func(c net.Conn){defer wg.Done();for{p,e:=readRecord(c);if e!=nil{return};if writeRecord(c,p)!=nil{return}}}(peer)
   go func(c net.Conn){defer wg.Done();for{p,e:=readRecord(c);if e!=nil{return};consume(p)}}(c)
   sends=append(sends,func(p []byte)error{return writeRecord(c,p)})
  }
  shutdown=func(){for _,c:=range clients{c.Close()};for _,c:=range servers{c.Close()};sa.Close();sb.Close()}
 }
 // Setup time excluded; all timestamps share a monotonic origin.
 phase:=time.Now();na.activate(phase);nb.activate(phase)
 queues:=make([]chan []byte,len(sends));var writers sync.WaitGroup
 for lane,send:=range sends{queues[lane]=make(chan []byte,64);writers.Add(1);go func(q chan []byte,send func([]byte)error){defer writers.Done();for p:=range q{t:=time.Now();e:=send(p);d:=float64(time.Since(t))/1e6;mu.Lock();if d>r.MaxWrite{r.MaxWrite=d};if e!=nil{r.WriteErrors++};mu.Unlock()}}(queues[lane],send)}
 sendMessage:=func(seq,flow uint64,size int){p:=make([]byte,size);binary.BigEndian.PutUint64(p,seq);binary.BigEndian.PutUint64(p[8:],flow);binary.BigEndian.PutUint64(p[16:],uint64(time.Since(start)));lane:=int(flow)%len(queues);select{case queues[lane]<-p:default:mu.Lock();r.WriteErrors++;mu.Unlock()}}
 tick:=time.NewTicker(10*time.Millisecond)
 for i:=range 100+count{<-tick.C;seq:=uint64(count+1);if i>=100{seq=uint64(i-100);r.Sent++};sendMessage(seq,uint64(i%4),256);if s.Load{sendMessage(uint64(count+2),4,1200);sendMessage(uint64(count+3),4,1200)}}
 tick.Stop();for _,q:=range queues{close(q)}
 // Finite observation window; undelivered records remain visible as missing.
 time.Sleep(2*time.Second)
 shutdown();writers.Wait();wg.Wait()
 mu.Lock();defer mu.Unlock();r.Received=len(r.RTT);r.Missing=r.Sent-r.Received
 sort.Float64s(r.RTT);r.P50=percentile(r.RTT,.5);r.P95=percentile(r.RTT,.95);r.P99=percentile(r.RTT,.99);r.Max=percentile(r.RTT,1)
 x,y:=na.snapshot(),nb.snapshot();r.Packets=x.Attempts+y.Attempts;r.WireBytes=x.Bytes+y.Bytes;r.Drops=x.Drops+y.Drops;r.QueueDrops=x.QueueDrops+y.QueueDrops
 return r
}
func main(){repeats:=flag.Int("repeats",3,"seeds");count:=flag.Int("count",400,"measured messages");only:=flag.String("only","","single variant smoke");flag.Parse();fmt.Fprintf(os.Stderr,"Go=%s OS=%s/%s count=%d repeats=%d\n",runtime.Version(),runtime.GOOS,runtime.GOARCH,*count,*repeats)
 enc:=json.NewEncoder(os.Stdout)
 for repeat:=range *repeats{for _,s:=range scenarios{for _,v:=range variants{if *only!=""&&v.Name!=*only{continue};r:=run(v,s,repeat,*count);must(enc.Encode(r));fmt.Fprintf(os.Stderr,"%s %s seed=%d n=%d/%d p95=%.1f max=%.1f late=%d\n",v.Name,s.Name,repeat,r.Received,r.Sent,r.P95,r.Max,r.Over100)}}}
}
