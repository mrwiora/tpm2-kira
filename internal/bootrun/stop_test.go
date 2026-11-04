package bootrun

import (
	"testing"
	"time"
)

// endingPart records its end, or hangs in it.
type endingPart struct {
	hang  chan struct{}
	ended chan struct{}
}

func (p *endingPart) start(*board)            {}
func (p *endingPart) released(*board, string) {}
func (p *endingPart) end(*board) {
	if p.hang != nil {
		<-p.hang
	}
	close(p.ended)
}

// A part that hangs in its end holds neither the others nor run past endWait.
func TestEndOfRunIsBounded(t *testing.T) {
	was := endWait
	endWait = 100 * time.Millisecond
	defer func() { endWait = was }()

	hung := &endingPart{hang: make(chan struct{}), ended: make(chan struct{})}
	defer close(hung.hang)
	good := &endingPart{ended: make(chan struct{})}
	s := &startedParts{}
	s.add(hung)
	s.add(good)
	begin := time.Now()
	s.end(&board{})
	if took := time.Since(begin); took > 2*time.Second {
		t.Errorf("the end took %s", took)
	}
	select {
	case <-good.ended:
	default:
		t.Error("the part behind the hung one was not ended")
	}
}
