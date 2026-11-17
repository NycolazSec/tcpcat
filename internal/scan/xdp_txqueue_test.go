//go:build linux

package scan

import (
	"testing"
	"time"
)

// withTxQueue swaps in a small TX queue and wait for one test.
func withTxQueue(t *testing.T, capacity int, wait time.Duration) {
	t.Helper()
	q, w := xdpTxQueue, xdpTxEnqueueWait
	xdpTxQueue, xdpTxEnqueueWait = make(chan xdpTxItem, capacity), wait
	t.Cleanup(func() { xdpTxQueue, xdpTxEnqueueWait = q, w })
}

// fakeFlusher stands in for xdpTxFlusher: after delay it takes one item and
// reports it sent (or not).
func fakeFlusher(delay time.Duration, ok bool) <-chan xdpTxItem {
	got := make(chan xdpTxItem, 1)
	go func() {
		time.Sleep(delay)
		it := <-xdpTxQueue
		if it.sent != nil {
			it.sent <- ok
		}
		got <- it
	}()
	return got
}

// A full queue used to fail the probe at once, and the port was reported
// FILTERED without having been probed. It must wait for room instead.
func TestTransmitXDPFramesWaitsForRoom(t *testing.T) {
	withTxQueue(t, 1, 2*time.Second)
	xdpTxQueue <- xdpTxItem{frame: []byte("already queued")}

	go func() {
		time.Sleep(50 * time.Millisecond)
		<-xdpTxQueue // the flusher takes the frame ahead of ours...
		it := <-xdpTxQueue
		it.sent <- true // ...then ours, and puts it on the ring
	}()
	start := time.Now()
	if !transmitXDPFrames(nil, [][]byte{[]byte("probe")}) {
		t.Fatal("transmitXDPFrames gave up although the queue freed up within the wait")
	}
	if waited := time.Since(start); waited < 40*time.Millisecond {
		t.Errorf("returned after %s: it should have waited for room, not dropped or overfilled", waited)
	}
}

// The probe's timeout starts when transmitXDPFrames returns, so it must not
// return before the flusher has actually put the frame on the ring.
func TestTransmitXDPFramesReturnsOnceSent(t *testing.T) {
	withTxQueue(t, 8, 2*time.Second)
	got := fakeFlusher(60*time.Millisecond, true)

	start := time.Now()
	if !transmitXDPFrames(nil, [][]byte{[]byte("probe")}) {
		t.Fatal("transmitXDPFrames reported failure for a frame the flusher sent")
	}
	if waited := time.Since(start); waited < 50*time.Millisecond {
		t.Errorf("returned after %s, before the flusher sent the frame (60 ms)", waited)
	}
	if it := <-got; string(it.frame) != "probe" || it.sent == nil {
		t.Errorf("flusher got %+v, want the probe frame carrying a sent signal", it)
	}
}

// A frame the flusher could not put on the ring (no free UMEM frame) used to
// vanish, and its probe waited out a timeout as if the target were silent.
func TestTransmitXDPFramesReportsDroppedFrame(t *testing.T) {
	withTxQueue(t, 8, 2*time.Second)
	fakeFlusher(0, false)
	if transmitXDPFrames(nil, [][]byte{[]byte("probe")}) {
		t.Fatal("transmitXDPFrames reported success for a frame the flusher dropped")
	}
}

// Fragments go out in order; only the last one carries the sent signal.
func TestTransmitXDPFramesSignalsOnLastFragment(t *testing.T) {
	withTxQueue(t, 8, 2*time.Second)
	done := make(chan bool, 1)
	go func() { done <- transmitXDPFrames(nil, [][]byte{[]byte("f1"), []byte("f2"), []byte("f3")}) }()
	for i, want := range []string{"f1", "f2", "f3"} {
		it := <-xdpTxQueue
		if string(it.frame) != want {
			t.Fatalf("fragment %d = %q, want %q", i, it.frame, want)
		}
		if last := i == 2; (it.sent != nil) != last {
			t.Fatalf("fragment %q: sent signal present = %v, want %v", it.frame, it.sent != nil, last)
		}
		if i == 2 {
			it.sent <- true
		}
	}
	if !<-done {
		t.Fatal("transmitXDPFrames failed although every fragment was sent")
	}
}

// When nothing drains the queue, the wait is bounded and the caller is told
// the frame was not sent.
func TestTransmitXDPFramesGivesUpAfterWait(t *testing.T) {
	withTxQueue(t, 1, 30*time.Millisecond)
	xdpTxQueue <- xdpTxItem{frame: []byte("stuck")}

	start := time.Now()
	if transmitXDPFrames(nil, [][]byte{[]byte("probe")}) {
		t.Fatal("transmitXDPFrames reported success with a queue that never had room")
	}
	if waited := time.Since(start); waited < 25*time.Millisecond || waited > time.Second {
		t.Errorf("gave up after %s, want about the 30 ms wait", waited)
	}
}
