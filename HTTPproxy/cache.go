package main

import (
	//"sort"
	"fmt"
	"io/ioutil"
	"time"
)

type Cache struct {
	Blk  map[string]Block
	Size int
}

type Block struct {
	Content      []byte
	CreateTime   time.Time
	LastModified string
	LastExtract  time.Time
	Using        bool
	Size         int
}

func NewCache() *Cache {
	return &Cache{
		make(map[string]Block),
		4096,
	}
}

func NewBlock(data []byte, LastModified string) *Block {
	return &Block{
		data,
		time.Now(),
		LastModified,
		time.Now(),
		true,
		len(data),
	}
}

func (c *Cache) Full() bool {
	if c.Size == len(c.Blk) {
		return true
	}
	return false
}

func (c *Cache) Find(uri string) *Block {
	blk, ok := c.Blk[uri]
	if ok {
		return &blk
	}
	return nil

}

func (c *Cache) Insert(uri string, b Block) error {
	cacheWrite.Lock()
	if c.Full() {
		err := c.delete()
		if err != nil {
			return err
		}
	}
	b.Using = false
	c.Blk[uri] = b
	cacheWrite.Unlock()
	return nil
}

func (c *Cache) delete() error {
	var i string
	max := 0
	for k, v := range c.Blk {
		tmp := time.Now().Nanosecond() - v.LastExtract.Nanosecond()
		if max <= tmp && !v.Using {
			max = tmp
			i = k
		}
	}
	delete(c.Blk, i)
	return nil
}

func (c *Cache) Write() {
	cacheWrite.Lock()
	b, err := Encode(cache)
	if err != nil {
		fmt.Println(err)
	}
	ioutil.WriteFile("cache.bk", b, 0777)
	// fmt.Println("@@@@@@@", len(b), cache)
	cacheWrite.Unlock()
}
