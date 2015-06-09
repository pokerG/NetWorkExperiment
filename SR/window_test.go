package SR

import (
	"strconv"
	"testing"
)

func TestSilding(t *testing.T) {
	wd := NewSlidingWindow(32)
	wd.Sliding()
	if wd.base != 0 {
		t.Error("Silding First Error")
	}
	wd.ack[0] = true
	wd.ack[1] = true
	wd.Sliding()
	if wd.base != 2 {
		t.Error("Silding Second Error")
	}
	wd.ack[10] = true
	if wd.base != 2 {
		t.Error("Silding Third Error")
	}
}

func TestSlidingContent(t *testing.T) {
	wd := NewSlidingWindow(10)
	for i := 0; i < 10; i++ {
		wd.content[i] = []byte(strconv.Itoa(i))
	}
	wd.ack[0] = true
	wd.ack[1] = true
	wd.ack[3] = true
	s := wd.Sliding()
	if string(s) != "0" {
		t.Error(wd.content)
		t.Error(s)
	}
}
