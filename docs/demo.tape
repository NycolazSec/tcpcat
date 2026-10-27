# Terminal demo for the README, recorded with vhs (https://github.com/charmbracelet/vhs).
#
#   go install github.com/charmbracelet/vhs@latest   # or: brew install vhs
#   vhs docs/demo.tape                                # writes docs/demo.gif
#   # then uncomment the ![tcpcat demo] line in README.md and commit the gif
#
# Keep it short (~10-12s) and scan ONLY an authorized host. scanme.nmap.org is
# the public target Nmap provides for scan testing. Run this where you already
# have sudo cached, or swap in a lab host so no password prompt is recorded.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 640
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 60ms
Set PlaybackSpeed 1.0

Hide
Type "clear" Enter
Show

Type "sudo tcpcat -sV -p 22,80,443 scanme.nmap.org"
Sleep 800ms
Enter

# Let the SYN + service-detection + CVE-lookup output stream in.
Sleep 9s

Type "# full JSON report:  add  -j report.json   |   SARIF:  --sarif report.sarif"
Sleep 2s
Enter
Sleep 1500ms
