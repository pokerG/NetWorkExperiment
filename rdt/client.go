package main

import (
	"flag"
	"github.com/pokerG/rdt"
	"time"
)

var address = flag.String("a", ":8888", "port")
var filename = flag.String("f", "1.jpg", "filename")

func main() {
	flag.Parse()
	client := rdt.NewClient(*address, *filename, time.Second)
	client.Start()
}
