package main

import (
	"strconv"
	"testing"
)

func TestCache(t *testing.T) {
	cache := NewCache()
	for i := 0; i < cache.size; i++ {
		cache.Insert(strconv.Itoa(i), *NewBlock([]byte(" "), ""))
	}
	if !cache.Full() {
		t.Error("Cache Insert Error")
	}
	if cache.Find("0") == nil {
		t.Error("Cache Find Error")
	}
	cache.delete()
	if cache.Full() {
		t.Error("Cache delete Error")
	}
	if cache.Find("0") != nil {
		t.Error(cache.blk)
	}
	if cache.Find(strconv.Itoa(cache.size-1)) == nil {
		t.Error("Cache delete error last blk")
	}
}

func TestURI(t *testing.T) {
	cache := NewCache()
	cache.Insert("http://csdnim.allyes.com/main/s?user=csdn|homepage|Recommend3&db=csdnim&border=0&local=yes&js=ie", *NewBlock([]byte(" "), ""))
	if cache.Find("http://csdnim.allyes.com/main/s?user=csdn|homepage|Recommend3&db=csdnim&border=0&local=yes&js=ie") == nil {
		t.Error("Find URI Error")
	}
}
