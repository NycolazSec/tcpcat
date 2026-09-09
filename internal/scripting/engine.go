package scripting

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
)

type ScriptExecutionResult struct {
	ScriptName string
	Output     map[string]string
	Error      string
}

type ScriptingEngine struct {
	runtime wazero.Runtime
	scripts map[string]wazero.CompiledModule
	timeout time.Duration
}

func New(scriptPath string, timeout time.Duration) (*ScriptingEngine, error) {
	ctx := context.Background()
	runtime := wazero.NewRuntime(ctx)

	engine := &ScriptingEngine{
		runtime: runtime,
		scripts: make(map[string]wazero.CompiledModule),
		timeout: timeout,
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

	instance, err := e.runtime.InstantiateModule(ctx, compiledMod, wazero.NewModuleConfig().WithName(name))
	if err != nil {
		return nil, fmt.Errorf("instantiation failed: %w", err)
	}
	defer instance.Close(ctx)

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
	defer deallocFunc.Call(ctx, ipPtr, ipSize)

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
	defer deallocFunc.Call(ctx, uint64(resultPtr), uint64(resultLen))

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
