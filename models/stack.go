package models

type Stack struct {
	Items []*Peer
}

func (s *Stack) Push(item *Peer) {
	s.Items = append(s.Items, item)
}

func (s *Stack) Pop() *Peer {
	if !s.IsEmpty() {
		val := s.Items[len(s.Items)-1]
		s.Items = s.Items[0 : len(s.Items)-1]
		return val
	}
	return nil
}

func (s *Stack) IsEmpty() bool {
	return len(s.Items) == 0
}

func (s *Stack) Peek() *Peer {
	return s.Items[len(s.Items)-1]
}

func (s *Stack) Len() int {
	return len(s.Items)
}
