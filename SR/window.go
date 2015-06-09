package SR

import (
	"fmt"
)

type SlidingWindow struct {
	base    int32
	nextSeq int32
	size    int32
	content [][]byte
	ack     []bool
	seq     []int
}

func NewSlidingWindow(size int32) *SlidingWindow {
	return &SlidingWindow{
		base:    0,
		nextSeq: 0,
		size:    size,
		content: make([][]byte, size),
		ack:     make([]bool, size),
	}
}

func (s *SlidingWindow) Sliding() []byte {
	var next int32
	next = -1
	for k, v := range s.ack {
		if v == false {
			next = int32(k)
			if k == 0 { //first seq havn't ack
				return nil
			}
			break
		}
	}
	var ctn []byte
	if next == -1 {
		for k, v := range s.content {
			ctn = append(ctn, v...)
			s.seq = append(s.seq, k+int(s.base))
		}
		s.content = make([][]byte, s.size)
		s.ack = make([]bool, s.size)
		s.base += s.size
	} else {
		for k, v := range s.content[:next] {
			ctn = append(ctn, v...)
			s.seq = append(s.seq, k+int(s.base))
		}
		for i, j := next, 0; i < s.size; i, j = i+1, j+1 {
			s.content[j] = s.content[i]
		}
		for i := s.size - next; i < s.size; i++ {
			s.content[i] = nil
		}
		// fmt.Println("!!!", s.content)
		// copy(s.content, s.content[next:])
		// copy(s.content[s.size-next:], make([][]byte, s.size-next))
		// fmt.Println("@@@", s.content)
		// fmt.Println("!!!", s.ack)
		copy(s.ack, s.ack[next:])
		copy(s.ack[s.size-next:], make([]bool, s.size-next))
		// fmt.Println("@@@", s.ack)
		fmt.Println()
		s.base += next
	}

	return ctn
}

func (s *SlidingWindow) Recv(rdt RdtConn) bool {
	s.content[rdt.header.Seq-s.base] = rdt.content
	s.ack[rdt.header.Seq-s.base] = true
	return true
}

func (s *SlidingWindow) NotFUll() bool {
	if s.nextSeq < s.base+s.size {
		return true
	}
	return false
}
