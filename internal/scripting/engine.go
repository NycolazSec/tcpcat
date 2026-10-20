package scripting

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// The script ABI (see docs/WASM_SDK.md and examples/wasm-dissector/).
//
// A module exports:
//
//	allocate(size i32) -> ptr i32
//	deallocate(ptr i32, size i32)
//	run(port i32, ip_ptr i32, ip_len i32) -> i64   // (ptr << 32) | len of a JSON object, or 0
//
// and may import one host function, the script's only way to reach the
// network:
//
//	tcpcat.probe(req_ptr, req_len, resp_ptr, resp_cap i32) -> i32
//
// probe opens a TCP connection to the port being scanned -- that host and
// port only, the script cannot choose another -- sends the request bytes (an
// empty request just reads the banner), and writes up to resp_cap bytes of
// the answer at resp_ptr. It returns the byte count, or a negative
// probeErr* code. Each run is limited to maxProbesPerRun probes and
// maxProbeResponse bytes per answer, so a script can neither hammer a
// fragile service nor be used to move bulk data.
const (
	HostModule       = "tcpcat"
	maxProbesPerRun  = 4
	maxProbeResponse = 64 * 1024
	probeIdle        = 300 * time.Millisecond // quiet time that ends a response

	probeErrConnect = -1 // could not connect, or the write failed
	probeErrBudget  = -2 // more than maxProbesPerRun probes in one run
	probeErrArgs    = -3 // request or response buffer outside the module's memory
)

type runState struct {
	addr   string
	probes int
}

type runStateKey struct{}

type ScriptExecutionResult struct {
	ScriptName string
	Output     map[string]string
	Error      string
}

type ScriptingEngine struct {
	runtime wazero.Runtime
	scripts map[string]wazero.CompiledModule
	timeout time.Duration
	// dial opens the connection behind tcpcat.probe; swapped in tests.
	dial func(ctx context.Context, addr string) (net.Conn, error)
}

func New(scriptPath string, timeout time.Duration) (*ScriptingEngine, error) {
	ctx := context.Background()
	runtime := wazero.NewRuntime(ctx)

	engine := &ScriptingEngine{
		runtime: runtime,
		scripts: make(map[string]wazero.CompiledModule),
		timeout: timeout,
		dial: func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
	}
	if _, err := runtime.NewHostModuleBuilder(HostModule).
		NewFunctionBuilder().WithFunc(engine.hostProbe).Export("probe").
		Instantiate(ctx); err != nil {
		engine.Close()
		return nil, fmt.Errorf("could not register the %s host module: %w", HostModule, err)
	}

	if scriptPath != "" {
		err := engine.loadAndCompileScripts(ctx, scriptPath)
		if err != nil {
			engine.Close()
			return nil, fmt.Errorf("could not load Wasm scripts: %w", err)
		}
		if len(engine.scripts) > 0 {
			log.Printf("[*] Wasm script engine initialized with %d script(s).", len(engine.scripts))
		} else {
			log.Printf("[!] Warning: No .wasm scripts were loaded from '%s'.", scriptPath)
		}
	}

	return engine, nil
}

func (e *ScriptingEngine) Close() {
	if e.runtime != nil {
		if err := e.runtime.Close(context.Background()); err != nil {
			log.Printf("[!] Error closing Wasm runtime: %v", err)
		}
	}
}

func (e *ScriptingEngine) loadAndCompileScripts(ctx context.Context, path string) error {
	scriptsFS := os.DirFS(path)
	return fs.WalkDir(scriptsFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".wasm") {
			return nil
		}

		content, err := fs.ReadFile(scriptsFS, p)
		if err != nil {
			log.Printf("[!] Warning: could not read Wasm script '%s': %v", p, err)
			return nil
		}

		compiledModule, err := e.runtime.CompileModule(ctx, content)
		if err != nil {
			log.Printf("[!] Wasm module compilation error '%s': %v", d.Name(), err)
			return nil
		}

		scriptName := strings.TrimSuffix(d.Name(), ".wasm")
		e.scripts[scriptName] = compiledModule
		return nil
	})
}

func (e *ScriptingEngine) RunAll(ip string, port int) []ScriptExecutionResult {
	if len(e.scripts) == 0 {
		return nil
	}

	resultsChan := make(chan ScriptExecutionResult, len(e.scripts))
	var wg sync.WaitGroup

	wg.Add(len(e.scripts))
	for name, runFunc := range e.scripts {
		go func(name string, compiledMod wazero.CompiledModule) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					resultsChan <- ScriptExecutionResult{ScriptName: name, Error: fmt.Sprintf("panic: %v", r)}
				}
			}()

			output, err := e.executeWasmScript(name, compiledMod, ip, port)
			if err != nil {
				log.Printf("[!] Script '%s' returned an error: %v", name, err)
				resultsChan <- ScriptExecutionResult{ScriptName: name, Error: err.Error()}
				return
			}
			if output != nil {
				resultsChan <- ScriptExecutionResult{ScriptName: name, Output: output}
			}
		}(name, runFunc)
	}

	wg.Wait()
	close(resultsChan)

	var results []ScriptExecutionResult
	for res := range resultsChan {
		results = append(results, res)
	}

	return results
}

func (e *ScriptingEngine) executeWasmScript(name string, compiledMod wazero.CompiledModule, ip string, port int) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	ctx = context.WithValue(ctx, runStateKey{}, &runState{addr: net.JoinHostPort(ip, strconv.Itoa(port))})

	// An anonymous instance per run: scripts run concurrently, one instance
	// per open port, and two instances can't share a module name. TinyGo
	// (and other "reactor" modules) initialise in _initialize, not _start.
	instance, err := e.runtime.InstantiateModule(ctx, compiledMod,
		wazero.NewModuleConfig().WithName("").WithStartFunctions("_initialize", "_start"))
	if err != nil {
		return nil, fmt.Errorf("instantiation failed: %w", err)
	}
	defer func() { _ = instance.Close(ctx) }()

	runFunc := instance.ExportedFunction("run")
	allocFunc := instance.ExportedFunction("allocate")
	deallocFunc := instance.ExportedFunction("deallocate")
	mem := instance.Memory()

	if runFunc == nil || allocFunc == nil || deallocFunc == nil {
		return nil, fmt.Errorf("script does not export required functions ('run', 'allocate', 'deallocate')")
	}

	ipSize := uint64(len(ip))
	results, err := allocFunc.Call(ctx, ipSize)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate memory for IP: %w", err)
	}
	ipPtr := results[0]
	defer func() { _, _ = deallocFunc.Call(ctx, ipPtr, ipSize) }()

	if !mem.Write(uint32(ipPtr), []byte(ip)) {
		return nil, fmt.Errorf("failed to write IP to Wasm memory")
	}

	packedResult, err := runFunc.Call(ctx, uint64(port), ipPtr, ipSize)
	if err != nil {
		return nil, fmt.Errorf("execution of 'run' function failed: %w", err)
	}

	resultPtr := uint32(packedResult[0] >> 32)
	resultLen := uint32(packedResult[0])

	if resultPtr == 0 || resultLen == 0 {
		return nil, nil
	}
	defer func() { _, _ = deallocFunc.Call(ctx, uint64(resultPtr), uint64(resultLen)) }()

	resultBytes, ok := mem.Read(resultPtr, resultLen)
	if !ok {
		return nil, fmt.Errorf("failed to read result from Wasm memory (ptr=%d, len=%d)", resultPtr, resultLen)
	}

	var output map[string]string
	if err := json.Unmarshal(resultBytes, &output); err != nil {
		return nil, fmt.Errorf("failed to parse JSON returned by script: %w", err)
	}

	return output, nil
}

// hostProbe implements tcpcat.probe (see the ABI comment at the top).
func (e *ScriptingEngine) hostProbe(ctx context.Context, m api.Module, reqPtr, reqLen, respPtr, respCap uint32) int32 {
	state, _ := ctx.Value(runStateKey{}).(*runState)
	if state == nil {
		return probeErrConnect
	}
	if state.probes >= maxProbesPerRun {
		return probeErrBudget
	}
	state.probes++

	if respCap > maxProbeResponse {
		respCap = maxProbeResponse
	}
	req, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok || !validRange(m.Memory(), respPtr, respCap) {
		return probeErrArgs
	}

	conn, err := e.dial(ctx, state.addr)
	if err != nil {
		return probeErrConnect
	}
	defer func() { _ = conn.Close() }()
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		_ = conn.SetDeadline(deadline)
	}
	if len(req) > 0 {
		if _, err := conn.Write(req); err != nil {
			return probeErrConnect
		}
	}

	// Read until the buffer is full, the peer closes, or it goes quiet for
	// probeIdle after having said something.
	buf := make([]byte, respCap)
	n := 0
	for n < len(buf) {
		if n > 0 {
			idle := time.Now().Add(probeIdle)
			if !hasDeadline || idle.Before(deadline) {
				_ = conn.SetReadDeadline(idle)
			}
		}
		read, err := conn.Read(buf[n:])
		n += read
		if err != nil {
			break
		}
	}
	if !m.Memory().Write(respPtr, buf[:n]) {
		return probeErrArgs
	}
	return int32(n) // #nosec G115 -- n <= maxProbeResponse
}

func validRange(mem api.Memory, ptr, size uint32) bool {
	return uint64(ptr)+uint64(size) <= uint64(mem.Size())
}
