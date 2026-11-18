package main

import (
 "math/rand/v2"
 "net"
 "sync"
 "time"
)

type scenario struct { Name string; Loss float64; Burst bool; Rate int; Load bool; Delay time.Duration }
type wireStats struct { Attempts, Bytes, Drops, QueueDrops int64 }
type delivery struct { when time.Time; data []byte; addr net.Addr }
type network struct {
 mu sync.Mutex
 rng *rand.Rand
 cfg scenario
 start time.Time
 next time.Time
 queue []delivery
 wake chan struct{}
 stop chan struct{}
 done chan struct{}
 closed bool
 stats wireStats
 pc net.PacketConn
 active bool
}
func newNetwork(cfg scenario, seed uint64)*network{
 n:=&network{rng:rand.New(rand.NewPCG(seed,31)),cfg:cfg,start:time.Now(),wake:make(chan struct{},1),stop:make(chan struct{}),done:make(chan struct{})}
 go n.run();return n
}
func(n *network)send(p []byte,a net.Addr,copies int)(int,error){
 n.mu.Lock();defer n.mu.Unlock()
 if n.closed{return 0,net.ErrClosed}
 for range copies {
  n.stats.Attempts++;n.stats.Bytes+=int64(len(p)+28)
  now:=time.Now();drop:=n.active && n.rng.Float64()<n.cfg.Loss
  if n.active && n.cfg.Burst && now.Sub(n.start)%time.Second < 50*time.Millisecond {drop=true}
  if drop{n.stats.Drops++;continue}
  if len(n.queue)>=4096{n.stats.QueueDrops++;continue}
  ready:=now
  if n.cfg.Rate>0 {if n.next.After(ready){ready=n.next};ready=ready.Add(time.Duration(int64(len(p)+28)*8*int64(time.Second)/int64(n.cfg.Rate)));n.next=ready}
  when:=ready.Add(n.cfg.Delay)
  n.queue=append(n.queue,delivery{when,append([]byte(nil),p...),a})
 }
 select{case n.wake<-struct{}{}:default:}
 captureUDP(n.pc.LocalAddr(),a,p)
 return len(p),nil
}
func(n *network)run(){
 defer close(n.done)
 for {
  n.mu.Lock()
  if len(n.queue)==0{n.mu.Unlock();select{case<-n.wake:continue;case<-n.stop:return}}
  item:=n.queue[0];wait:=time.Until(item.when);n.mu.Unlock()
  if wait>0{t:=time.NewTimer(wait);select{case<-t.C:case<-n.stop:t.Stop();return}}
  n.mu.Lock();if n.closed{n.mu.Unlock();return};n.queue[0]=delivery{};n.queue=n.queue[1:];n.mu.Unlock()
  n.pc.WriteTo(item.data,item.addr)
 }
}
func(n *network)close(){n.mu.Lock();if !n.closed{n.closed=true;close(n.stop)};n.mu.Unlock();<-n.done}
func(n *network)snapshot()wireStats{n.mu.Lock();defer n.mu.Unlock();return n.stats}
func(n *network)activate(at time.Time){n.mu.Lock();n.start=at;n.active=true;n.mu.Unlock()}
type impaired struct{net.PacketConn; network *network; copies int; once sync.Once}
func endpoint(n *network,copies int)*impaired{pc,e:=net.ListenPacket("udp4","127.0.0.1:0");must(e);n.pc=pc;return &impaired{PacketConn:pc,network:n,copies:copies}}
func(p *impaired)WriteTo(b []byte,a net.Addr)(int,error){return p.network.send(b,a,p.copies)}
func(p *impaired)Close()error{var e error;p.once.Do(func(){p.network.close();e=p.PacketConn.Close()});return e}

// delayedConn adds a fixed one-way delay to every Write, mirroring the UDP
// network's send-side queue: Write copies and returns immediately, a background
// loop flushes after the delay. A symmetric pair (one per endpoint) models
// cfg.Delay one-way in each direction without blocking the sender on the delay.
type delayedWrite struct{ b []byte; when time.Time }
type delayedConn struct{
 net.Conn
 delay time.Duration
 q chan delayedWrite
 done chan struct{}
 wg sync.WaitGroup
}
func wrapDelay(c net.Conn,d time.Duration)net.Conn{
 if d<=0{return c}
 x:=&delayedConn{Conn:c,delay:d,q:make(chan delayedWrite,128),done:make(chan struct{})}
 x.wg.Add(1);go x.flush();return x
}
func(x *delayedConn)flush(){
 defer x.wg.Done()
 for{select{case w:=<-x.q:if wait:=time.Until(w.when);wait>0{time.Sleep(wait)};if fullWrite(x.Conn,w.b)!=nil{return};case<-x.done:return}}
}
func(x *delayedConn)Write(p []byte)(int,error){
 b:=append([]byte(nil),p...)
 select{case x.q<-delayedWrite{b,time.Now().Add(x.delay)}:return len(p),nil;case<-x.done:return 0,net.ErrClosed}
}
func(x *delayedConn)Close()error{select{case<-x.done:default:close(x.done)};x.wg.Wait();return x.Conn.Close()}
