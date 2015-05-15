package main

import (
	"testing"
)

func TestFilter(t *testing.T) {
	f := NewFilter()
	if !f.FilterURL("cn.bing.com:80") {
		t.Errorf("Filter URL Error")
		t.Error(f.Get("url_filter").StringArray())
	}
}
