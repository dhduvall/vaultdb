package vaultdb

import (
	"sync"
)

// fanout is a fan-out notification multiplexer for channels.  It receives a
// notification on an input channel designated at creation time, and copies that
// to all output channels added by AddReceiver.
type fanout struct {
	input  chan struct{}
	output []chan struct{}
	sync.Mutex
}

// newfanout creates a new fanout with a given input channel.
func newfanout(input chan struct{}) *fanout {
	fo := &fanout{input: input}

	go func() {
		for n := range input {
			fo.Lock()
			for _, out := range fo.output {
				out <- n
			}
			fo.Unlock()
		}
		fo.Lock()
		for _, out := range fo.output {
			close(out)
		}
		fo.Unlock()
	}()

	return fo
}

// addReceiver creates a new output channel, adds it to the list, and returns
// it.
func (fo *fanout) addReceiver() chan struct{} {
	c := make(chan struct{})
	fo.Lock()
	fo.output = append(fo.output, c)
	fo.Unlock()
	return c
}

// notify sends the notification to the input channel (and thus to all the
// receivers).
func (fo *fanout) notify() {
	fo.input <- struct{}{}
}
