# Terminal demo for the README, recorded with vhs (https://github.com/charmbracelet/vhs).
#
#   brew install vhs          # (or: go install github.com/charmbracelet/vhs@latest)
#   vhs docs/demo.tape        # writes docs/demo.gif
#
# Uses a TCP connect scan (-sT) so it runs WITHOUT root -- no sudo password
# prompt gets recorded, and anyone can reproduce it verbatim. scanme.nmap.org
# is the public host Nmap provides for scan testing. The PATH export below lets
# the command read as a clean `tcpcat ...`; it assumes you ran `go build -o
# tcpcat ./cmd/tcpcat` (or have the release binary) in the repo root.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 760
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 55ms

Hide
Type "export PATH=$PWD:$PATH" Enter
Type "clear" Enter
Show

Type "tcpcat -sT -sV -p 22,80,443 scanme.nmap.org"
Sleep 700ms
Enter

# Host discovery -> open ports -> service/version + weak-crypto findings ->
# CVE correlation via the OSV API. The real scan takes ~11s.
Sleep 13s
