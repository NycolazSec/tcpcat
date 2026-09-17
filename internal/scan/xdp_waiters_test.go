//go:build linux

package scan

import (
	"sync"
	"testing"
	"time"
)

func TestXDPWaiterDelivers(t *testing.T) {
	ch, release := registerXDPWaiter("10.0.0.1:80")
	defer release()

	deliverXDPResult("10.0.0.1:80", xdpResponse{state: StateOpen, osName: "Linux"})

	select {
	case resp := <-ch:
		if resp.state != StateOpen || resp.osName != "Linux" {
			t.Errorf("got %+v, want open/Linux", resp)
		}
	case <-time.After(time.Second):
		t.Fatal("delivery to a registered waiter never arrived")
	}
}

func TestXDPDeliverNoWaiterIsDropped(t *testing.T) {
	// A reply whose probe already finished/timed out has no waiter. It must
	// be dropped silently rather than panic or leak -- the old sync.Map left
	// exactly these entries behind forever.
	deliverXDPResult("203.0.113.9:1234", xdpResponse{state: StateClosed})
	if _, ok := xdpWaiters.Load("203.0.113.9:1234"); ok {
		t.Error("a delivery with no waiter must not create a map entry")
	}
}

func TestXDPDeliverIsNonBlocking(t *testing.T) {
	// The single RX loop must never stall on a slow/already-satisfied
	// consumer: a second delivery to a cap-1 channel is dropped, not blocked.
	ch, release := registerXDPWaiter("10.0.0.2:443")
	defer release()

	done := make(chan struct{})
	go func() {
		deliverXDPResult("10.0.0.2:443", xdpResponse{state: StateOpen})
		deliverXDPResult("10.0.0.2:443", xdpResponse{state: StateClosed}) // must not block
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("second delivery blocked the RX loop")
	}

	if resp := <-ch; resp.state != StateOpen {
		t.Errorf("first delivery = %+v, want the buffered open result", resp)
	}
}

func TestXDPReleaseStopsDelivery(t *testing.T) {
	ch, release := registerXDPWaiter("10.0.0.3:22")
	release()

	deliverXDPResult("10.0.0.3:22", xdpResponse{state: StateOpen})

	select {
	case resp := <-ch:
		t.Errorf("received %+v after release; a released waiter must get nothing", resp)
	case <-time.After(50 * time.Millisecond):
		// expected: nothing delivered to a released waiter
	}
}

func TestXDPWaiterConcurrentDeliverRace(t *testing.T) {
	// Exercise register/deliver/release from many goroutines at once under
	// -race, the way a real high-rate scan drives thousands of probes.
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "10.1.2.3:" + time.Duration(i).String()
			ch, release := registerXDPWaiter(key)
			defer release()
			go deliverXDPResult(key, xdpResponse{state: StateOpen})
			select {
			case <-ch:
			case <-time.After(time.Second):
			}
		}(i)
	}
	wg.Wait()
}
