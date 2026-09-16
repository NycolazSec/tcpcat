package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// A scan over a large space (a /16, or every port on a host) can take long
// enough that an interruption -- Ctrl-C, a dropped SSH session, a laptop
// lid -- throws away real work. A checkpoint records each result as it is
// produced so the same command, re-run with the same --resume file, skips
// what is already done and finishes the rest, the way nmap's --resume and
// masscan's --resume do.
//
// The file is JSON Lines: one serialized TargetResult per line. That makes
// it both the resume state and a complete record of the finished portion,
// so resuming reconstructs the full result set rather than only the
// remaining tail.

// checkpoint appends completed results to a file and knows which
// target/port pairs are already recorded.
type checkpoint struct {
	file    *os.File
	writer  *bufio.Writer
	done    map[string]struct{}
	results []TargetResult
}

// checkpointKey identifies one scanned unit of work.
func checkpointKey(ip string, port int) string {
	return ip + ":" + strconv.Itoa(port)
}

// openCheckpoint loads any results already recorded in path (an absent file
// is fine -- a fresh scan), then opens it for appending. The returned
// checkpoint's `results` holds the prior results so the caller can seed its
// output, and `done` holds their keys so the caller can skip them.
func openCheckpoint(path string) (*checkpoint, error) {
	cp := &checkpoint{done: make(map[string]struct{})}

	// Read whatever is already there. A missing file is the normal
	// first-run case, not an error.
	if existing, err := os.Open(path); err == nil {
		scanner := bufio.NewScanner(existing)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		line := 0
		for scanner.Scan() {
			line++
			raw := scanner.Bytes()
			if len(raw) == 0 {
				continue
			}
			var r TargetResult
			if err := json.Unmarshal(raw, &r); err != nil {
				_ = existing.Close()
				return nil, fmt.Errorf("checkpoint %s is corrupt at line %d: %w", path, line, err)
			}
			cp.done[checkpointKey(r.IP, r.Port)] = struct{}{}
			cp.results = append(cp.results, r)
		}
		if err := scanner.Err(); err != nil {
			_ = existing.Close()
			return nil, fmt.Errorf("reading checkpoint %s: %w", path, err)
		}
		_ = existing.Close()
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("opening checkpoint %s: %w", path, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening checkpoint %s for append: %w", path, err)
	}
	cp.file = f
	cp.writer = bufio.NewWriter(f)
	return cp, nil
}

// isDone reports whether a target/port pair is already recorded, so the
// dispatcher can skip re-scanning it.
func (c *checkpoint) isDone(ip string, port int) bool {
	if c == nil {
		return false
	}
	_, ok := c.done[checkpointKey(ip, port)]
	return ok
}

// record appends one freshly completed result. Errors are non-fatal: a
// checkpoint that can't be written shouldn't abort a scan that is otherwise
// succeeding, so the failure is surfaced by the caller at close, not here.
func (c *checkpoint) record(r TargetResult) {
	if c == nil {
		return
	}
	data, err := json.Marshal(r)
	if err != nil {
		return
	}
	_, _ = c.writer.Write(data)
	_ = c.writer.WriteByte('\n')
}

// priorResults are the results loaded from an existing checkpoint, to be
// merged into the final output so a resumed scan reports the whole space.
func (c *checkpoint) priorResults() []TargetResult {
	if c == nil {
		return nil
	}
	return c.results
}

func (c *checkpoint) close() error {
	if c == nil {
		return nil
	}
	if err := c.writer.Flush(); err != nil {
		_ = c.file.Close()
		return err
	}
	return c.file.Close()
}
