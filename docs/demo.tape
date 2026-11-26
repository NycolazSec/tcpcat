# Terminal demo for the README, recorded with vhs (https://github.com/charmbracelet/vhs).
#
#   brew install vhs          # (or: go install github.com/charmbracelet/vhs@latest)
#   vhs docs/demo.tape        # writes docs/demo.gif
#
# Uses a TCP connect scan (-sT) so it runs WITHOUT root -- no sudo password
# prompt gets recorded, and anyone can reproduce it verbatim. scanme.nmap.org
# is the public host Nmap provides for scan testing. --ai-deep adds tcpcat's
# AI: how the scan went, what the machine is, and the fixes in order. Its
# follow-up checks are read-only (one connection per open port, the SSH
# login methods without any credential, one HTTP request). The PATH export below lets
# the command read as a clean `tcpcat ...`; it assumes you ran `go build -o
# tcpcat ./cmd/tcpcat` (or have the release binary) in the repo root.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1180
Set Height 1040
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 55ms

Hide
Type "export PATH=$PWD:$PATH" Enter
Type "clear" Enter
Show

Type "tcpcat -sT -sV --ai-deep -p 22,80,443 scanme.nmap.org"
Sleep 700ms
Enter

# Host discovery -> open ports -> service/version + weak-crypto findings ->
# CVE correlation via the OSV API -> the AI's thorough analysis, with its
# spinner while it checks. The whole run takes ~12s; then hold the last frame
# long enough to read the plan.
Sleep 16s
Sleep 8s
