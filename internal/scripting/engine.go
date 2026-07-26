package scripting

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"
	"time"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
)

type ScriptExecutionResult struct {
	ScriptName string
	Output     map[string]string
}

type ScriptFunc func(map[string]interface{}) map[string]string

type ScriptingEngine struct {
	scripts map[string]ScriptFunc
	timeout time.Duration
}

func New(scriptPath string, timeout time.Duration) (*ScriptingEngine, error) {
	engine := &ScriptingEngine{
		scripts: make(map[string]ScriptFunc),
		timeout: timeout,
	}

	err := engine.loadAndCompileScripts(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("impossible de charger les scripts: %w", err)
	}
	if len(engine.scripts) > 0 {
		log.Printf("[*] Moteur de scripts initialisé avec %d script(s).", len(engine.scripts))
	} else {
		log.Printf("[!] Avertissement: Aucun script n'a été chargé depuis '%s'.", scriptPath)
	}

	return engine, nil
}

func (e *ScriptingEngine) loadAndCompileScripts(path string) error {
	goPath, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("impossible de déterminer le GoPath pour le moteur de scripts: %w", err)
	}
	scriptsFS := os.DirFS(path)
	return fs.WalkDir(scriptsFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}

		content, err := fs.ReadFile(scriptsFS, p)
		if err != nil {
			log.Printf("[!] Avertissement: impossible de lire le script '%s': %v", p, err)
			return nil
		}

		i := interp.New(interp.Options{
			GoPath: goPath,
		})

		i.Use(stdlib.Symbols)

		_, err = i.Eval(string(content))
		if err != nil {
			log.Printf("[!] Erreur de compilation du script '%s': %v", d.Name(), err)
			return nil
		}

		v, err := i.Eval("Run")
		if err != nil {
			log.Printf("[!] Le script '%s' ne contient pas de fonction 'Run'", d.Name())
			return nil
		}

		runFunc, ok := v.Interface().(func(map[string]interface{}) map[string]string)
		if !ok {
			log.Printf("[!] La signature de la fonction 'Run' dans '%s' est invalide. Attendu: 'func(map[string]interface{}) map[string]string'", d.Name())
			return nil
		}

		scriptName := strings.TrimSuffix(d.Name(), ".go")
		e.scripts[scriptName] = runFunc
		return nil
	})
}

func (e *ScriptingEngine) RunAll(ip string, port int) []ScriptExecutionResult {
	if len(e.scripts) == 0 {
		return nil
	}

	var results []ScriptExecutionResult
	scriptTarget := map[string]interface{}{
		"IP":   ip,
		"Port": port,
	}

	for name, runFunc := range e.scripts {
		resultChan := make(chan map[string]string, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[!] Le script '%s' a provoqué une panique: %v", name, r)
				}
			}()
			resultChan <- runFunc(scriptTarget)
		}()

		select {
		case result := <-resultChan:
			if result != nil && len(result) > 0 {
				results = append(results, ScriptExecutionResult{ScriptName: name, Output: result})
			}
		case <-time.After(e.timeout):
			log.Printf("[!] Le script '%s' a dépassé le temps imparti (timeout)", name)
		}
	}
	return results
}
