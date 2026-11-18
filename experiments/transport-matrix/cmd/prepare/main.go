package main

import (
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
)

func main() {
 out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/anacrolix/go-utp").Output()
 must(err)
 upstream:=strings.TrimSpace(string(out))
 dir,err:=os.MkdirTemp("","btawg-source-");must(err)
 local:=filepath.Join(dir,"utp")
 must(exec.Command("cp","-a",upstream,local).Run())
 must(exec.Command("chmod","-R","u+w",local).Run())
 source := filepath.Join(local, "purego", "conn.go")
 b, err := os.ReadFile(source); must(err)
 original := "if i != (c.seqNr-1)&ackNrMask || c.curWindowPackets == 1 || pkt.payload >= ps {"
 if strings.Count(string(b), original) != 1 { panic("pinned Nagle condition changed; refusing overlay") }
 text := strings.Replace(string(b), original, "if MatrixDisableNagle || i != (c.seqNr-1)&ackNrMask || c.curWindowPackets == 1 || pkt.payload >= ps {", 1)
 // The benchmark sets this only between cases after every socket has closed.
 text += "\n// MatrixDisableNagle is an experiment-only send-policy switch.\nvar MatrixDisableNagle bool\n"
 must(os.WriteFile(source,[]byte(text),0600))
 mod,err:=os.ReadFile("go.mod");must(err)
 mod=append(mod,[]byte("\nreplace github.com/anacrolix/go-utp => "+local+"\n")...)
 must(os.WriteFile(filepath.Join(dir,"go.mod"),mod,0600))
 sum,err:=os.ReadFile("go.sum");must(err)
 must(os.WriteFile(filepath.Join(dir,"go.sum"),sum,0600))
 fmt.Println(dir)
}
func must(err error){if err!=nil{panic(err)}}
