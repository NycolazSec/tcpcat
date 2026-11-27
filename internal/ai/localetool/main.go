// Command localetool helps translate tcpcat's AI (see internal/ai/locales).
//
//	go run ./internal/ai/localetool template > internal/ai/locales/TEMPLATE.yaml
//	go run ./internal/ai/localetool template es   # es.yaml, with what is still missing
//	go run ./internal/ai/localetool status        # how much of each language is translated
//	go run ./internal/ai/localetool check         # what CI checks on every locale file
//
// Run it from the repository root.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/NycolazSec/tcpcat/internal/ai"
)

// phraseDirs hold the command line's phrases: msg(lang, en, fr) calls and
// [2]string{en, fr} pairs.
var phraseDirs = []string{"cmd/tcpcat", "internal/ai/model"}

// localesDir is where the translations live, from the repository root.
const localesDir = "internal/ai/locales"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "template":
		code := ""
		if len(os.Args) > 2 {
			code = os.Args[2]
		}
		var out string
		out, err = template(".", code)
		if err == nil {
			fmt.Print(out)
		}
	case "status":
		err = status(".")
	case "check":
		var problems []string
		problems, err = checkAll(".")
		for _, p := range problems {
			fmt.Println(p)
		}
		if err == nil && len(problems) > 0 {
			os.Exit(1)
		}
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "localetool:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: localetool template [code] | status | check")
	os.Exit(2)
}

// Phrase is one phrase of the command line, with where it was found.
type Phrase struct {
	EN, FR, Where string
}

// phrases collects the command line's phrases, sorted by English text.
func phrases(root string) ([]Phrase, error) {
	seen := map[string]Phrase{}
	for _, dir := range phraseDirs {
		files, err := filepath.Glob(filepath.Join(root, dir, "*.go"))
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, file, nil, 0)
			if err != nil {
				return nil, err
			}
			add := func(en, fr ast.Expr) {
				e, ok1 := literal(en)
				r, ok2 := literal(fr)
				if !ok1 || !ok2 || e == "" {
					return
				}
				if _, dup := seen[e]; !dup {
					seen[e] = Phrase{EN: e, FR: r, Where: filepath.ToSlash(filepath.Join(dir, filepath.Base(file)))}
				}
			}
			collect(f, add)
		}
	}
	out := make([]Phrase, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EN < out[j].EN })
	return out, nil
}

// collect finds the (English, French) pairs of a file: msg(lang, en, fr),
// calls to closures declared func(en, fr string), and [2]string literals,
// including the elements of [][2]string and map[K][2]string literals.
func collect(f *ast.File, add func(en, fr ast.Expr)) {
	pairFuncs := map[string]bool{"msg": true}
	ast.Inspect(f, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if id, ok := as.Lhs[0].(*ast.Ident); ok {
				if fl, ok := as.Rhs[0].(*ast.FuncLit); ok && enFrParams(fl.Type) {
					pairFuncs[id.Name] = true
				}
			}
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			id, ok := x.Fun.(*ast.Ident)
			if !ok || !pairFuncs[id.Name] {
				return true
			}
			switch {
			case id.Name == "msg" && len(x.Args) == 3:
				add(x.Args[1], x.Args[2])
			case id.Name != "msg" && len(x.Args) == 2:
				add(x.Args[0], x.Args[1])
			}
		case *ast.CompositeLit:
			if isPair(x.Type) {
				if len(x.Elts) == 2 {
					add(x.Elts[0], x.Elts[1])
				}
				return true
			}
			if !holdsPairs(x.Type) {
				return true
			}
			for _, el := range x.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					el = kv.Value
				}
				if c, ok := el.(*ast.CompositeLit); ok && c.Type == nil && len(c.Elts) == 2 {
					add(c.Elts[0], c.Elts[1])
				}
			}
		}
		return true
	})
}

func enFrParams(t *ast.FuncType) bool {
	var names []string
	for _, p := range t.Params.List {
		id, ok := p.Type.(*ast.Ident)
		if !ok || id.Name != "string" {
			return false
		}
		for _, n := range p.Names {
			names = append(names, n.Name)
		}
	}
	return len(names) == 2 && names[0] == "en" && names[1] == "fr"
}

// isPair reports whether t is [2]string.
func isPair(t ast.Expr) bool {
	at, ok := t.(*ast.ArrayType)
	if !ok || at.Len == nil {
		return false
	}
	l, ok := at.Len.(*ast.BasicLit)
	id, ok2 := at.Elt.(*ast.Ident)
	return ok && ok2 && l.Value == "2" && id.Name == "string"
}

// holdsPairs reports whether t is []([2]string) or map[K][2]string.
func holdsPairs(t ast.Expr) bool {
	switch x := t.(type) {
	case *ast.ArrayType:
		return x.Len == nil && isPair(x.Elt)
	case *ast.MapType:
		return isPair(x.Value)
	}
	return false
}

func literal(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	return s, err == nil
}

// template writes the file translators start from. With a language code, it
// keeps what that language already translates.
func template(root, code string) (string, error) {
	ps, err := phrases(root)
	if err != nil {
		return "", err
	}
	have := &ai.Locale{}
	if code != "" {
		path := filepath.Join(root, localesDir, code+".yaml")
		if _, err := os.Stat(path); err == nil {
			if have, err = ai.ParseLocale(os.DirFS(filepath.Join(root, localesDir)), code+".yaml"); err != nil {
				return "", err
			}
		}
	}
	var b strings.Builder
	if code == "" {
		b.WriteString(`# The starting point of a translation of tcpcat's AI. Copy this file to
# <code>.yaml in this directory (es.yaml, de.yaml, pt-BR.yaml...), translate
# what you can, and open a pull request: see README.md here. Any text left
# empty is shown in English, so a partial translation is welcome.
#
# Keep every %d, %s, %.0f... : tcpcat puts numbers and names there. You may
# move them; to change their order, write %[2]s for the second one, and so
# on. Write %% for a percent sign.
#
# Generated by: go run ./internal/ai/localetool template

`)
	} else {
		fmt.Fprintf(&b, "# tcpcat's AI in %s. See README.md in this directory.\n\n", code)
	}
	fmt.Fprintf(&b, "name: %s # the language's name, in that language\n", quote(have.Name))
	fmt.Fprintf(&b, "decimal: %s # decimal mark: \".\" or \",\"\n", quote(def(have.Decimal, ".")))
	fmt.Fprintf(&b, "thousands: %s # between groups of three digits: \",\", \".\", \" \" or \"none\"\n", quote(def(have.Thousands, ",")))
	fmt.Fprintf(&b, "percent: %s # a percentage, %%s is the number: \"%%s%%%%\" or \"%%s %%%%\"\n", quote(def(have.Percent, "%s%%")))
	b.WriteString("\n# What the AI says about each port and each scan (internal/ai).\nmessages:\n")
	for _, m := range ai.Catalog() {
		fmt.Fprintf(&b, "  # en: %s\n  # fr: %s\n  %s: %s\n", comment(m.EN), comment(m.FR), m.ID, quote(have.Messages[m.ID]))
	}
	b.WriteString("\n# The command line's own words. The left side is the English text: keep it\n# as it is, and translate the right side.\nphrases:\n")
	for _, p := range ps {
		fmt.Fprintf(&b, "  # fr: %s\n  %s: %s\n", comment(p.FR), quote(p.EN), quote(have.Phrases[p.EN]))
	}
	return b.String(), nil
}

func def(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// quote writes s as a YAML double-quoted string.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func comment(s string) string { return strings.ReplaceAll(s, "\n", `\n`) }

// status prints how much of each language is translated.
func status(root string) error {
	ps, err := phrases(root)
	if err != nil {
		return err
	}
	cat := ai.Catalog()
	codes, err := localeCodes(root)
	if err != nil {
		return err
	}
	total := len(cat) + len(ps)
	fmt.Printf("%d texts: %d messages, %d phrases\n", total, len(cat), len(ps))
	for _, code := range codes {
		l, err := ai.ParseLocale(os.DirFS(filepath.Join(root, localesDir)), code+".yaml")
		if err != nil {
			fmt.Printf("%-8s unreadable: %v\n", code, err)
			continue
		}
		done := 0
		for _, m := range cat {
			if l.Messages[m.ID] != "" {
				done++
			}
		}
		for _, p := range ps {
			if l.Phrases[p.EN] != "" {
				done++
			}
		}
		fmt.Printf("%-8s %-14s %3d%% (%d/%d)\n", code, l.Name, 100*done/total, done, total)
	}
	return nil
}

var codeRE = regexp.MustCompile(`^[a-z]{2,3}(-([A-Z]{2}|[A-Z][a-z]{3}))?$`)

// localeCodes lists the language files of the locales directory.
func localeCodes(root string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(root, localesDir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	var codes []string
	for _, f := range files {
		if filepath.Base(f) == ai.TemplateFile {
			continue
		}
		codes = append(codes, strings.TrimSuffix(filepath.Base(f), ".yaml"))
	}
	sort.Strings(codes)
	return codes, nil
}

// checkAll checks every locale file and returns what is wrong, one line each.
func checkAll(root string) ([]string, error) {
	ps, err := phrases(root)
	if err != nil {
		return nil, err
	}
	phrase := map[string]bool{}
	for _, p := range ps {
		phrase[p.EN] = true
	}
	english := map[string]string{}
	for _, m := range ai.Catalog() {
		english[m.ID] = m.EN
	}
	codes, err := localeCodes(root)
	if err != nil {
		return nil, err
	}
	var problems []string
	for _, code := range codes {
		file := code + ".yaml"
		bad := func(format string, args ...any) {
			problems = append(problems, file+": "+fmt.Sprintf(format, args...))
		}
		if code == "en" || code == "fr" || !codeRE.MatchString(code) {
			bad("the file name must be a language code other than en and fr, such as es or pt-BR")
		}
		l, err := ai.ParseLocale(os.DirFS(filepath.Join(root, localesDir)), file)
		if err != nil {
			bad("not valid YAML: %v", err)
			continue
		}
		if strings.TrimSpace(l.Name) == "" {
			bad("name: write the language's name, in that language")
		}
		if l.Decimal != "" && l.Decimal != "." && l.Decimal != "," {
			bad("decimal must be \".\" or \",\"")
		}
		if l.Percent != "" {
			if v, err := verbs(l.Percent); err != nil || len(v) != 1 || v[1] != 's' {
				bad("percent must hold exactly one %%s, and %%%% for the percent sign")
			}
		}
		for id, s := range l.Messages {
			en, ok := english[id]
			switch {
			case !ok:
				bad("messages: %q is not a message of tcpcat's AI (renamed or removed?)", id)
			case s != "":
				if err := sameVerbs(en, s); err != nil {
					bad("messages: %s: %v", id, err)
				}
			}
		}
		for en, s := range l.Phrases {
			switch {
			case !phrase[en]:
				bad("phrases: %q is not a phrase of the command line (changed in English?)", en)
			case s != "":
				if err := sameVerbs(en, s); err != nil {
					bad("phrases: %q: %v", en, err)
				}
			}
		}
	}
	sort.Strings(problems)
	return problems, nil
}

// sameVerbs checks that a translation uses the same formatting verbs as
// the English text, in any order.
func sameVerbs(en, tr string) error {
	ve, err := verbs(en)
	if err != nil {
		return nil // not a format string in English: nothing to compare
	}
	vt, err := verbs(tr)
	if err != nil {
		return fmt.Errorf("%v (write %%%% for a percent sign)", err)
	}
	if len(ve) == 0 && len(vt) == 0 {
		return nil
	}
	if fmt.Sprint(ve) != fmt.Sprint(vt) {
		return fmt.Errorf("keep the placeholders of the English text (%s), found %s", list(ve), list(vt))
	}
	return nil
}

// verbs maps each argument a format string uses to its verb letter.
func verbs(s string) (map[int]byte, error) {
	out := map[int]byte{}
	arg := 1
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		i++
		if i < len(s) && s[i] == '%' {
			continue
		}
		for i < len(s) && strings.IndexByte("+-# 0", s[i]) >= 0 {
			i++
		}
		explicit := func() {
			if i < len(s) && s[i] == '[' {
				j := strings.IndexByte(s[i:], ']')
				if j > 0 {
					if n, err := strconv.Atoi(s[i+1 : i+j]); err == nil {
						arg = n
						i += j + 1
					}
				}
			}
		}
		explicit()
		for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
			i++
		}
		explicit()
		if i >= len(s) || !(s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z') {
			return nil, fmt.Errorf("a %% sign that is not a placeholder")
		}
		out[arg] = s[i]
		arg++
	}
	return out, nil
}

func list(v map[int]byte) string {
	var keys []int
	for k := range v {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	var s []string
	for _, k := range keys {
		s = append(s, fmt.Sprintf("%%[%d]%c", k, v[k]))
	}
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, " ")
}
