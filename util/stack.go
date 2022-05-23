package util

type StackEntry struct {
	Node       []byte
	NodeHeight int
}

type Stack []*StackEntry

func (s *Stack) IsEmpty() bool {
	return len(*s) == 0
}

func (s *Stack) Push(stackEntry *StackEntry) {
	*s = append(*s, stackEntry)
}

func (s *Stack) Pop() *StackEntry {
	if s.IsEmpty() {
		return nil
	} else {
		element := (*s)[len(*s)-1] // Get top element
		*s = (*s)[:len(*s)-1]      // Remove top element
		return element
	}
}

func (s *Stack) Peek() *StackEntry {
	if s.IsEmpty() {
		return nil
	} else {
		element := (*s)[len(*s)-1] // Get top element
		return element
	}
}
