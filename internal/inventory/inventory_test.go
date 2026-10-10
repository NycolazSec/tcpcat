package inventory

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0000000000000000 100 0 0 10 0
   2: 0F02000A:0016 6402000A:D431 01 00000000:00000000 02:00095D6B 00000000     0        0 1003 4 0000000000000000 20 4 30 10 -1
`

const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1388 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2002 1 0000000000000000 100 0 0 10 0
`

func TestParseProcNetTCP(t *testing.T) {
	v4, err := ParseProcNetTCP(procTCP, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []Listener{{Address: "127.0.0.1", Port: 8080, Inode: 1001}, {Address: "0.0.0.0", Port: 22, Inode: 1002}}
	if !reflect.DeepEqual(v4, want) {
		t.Errorf("v4 = %+v", v4) // the ESTABLISHED line must be skipped
	}
	v6, err := ParseProcNetTCP(procTCP6, true)
	if err != nil {
		t.Fatal(err)
	}
	want6 := []Listener{{Address: "::", Port: 5000, Inode: 2001}, {Address: "::1", Port: 80, Inode: 2002}}
	if !reflect.DeepEqual(v6, want6) {
		t.Errorf("v6 = %+v", v6)
	}
	if _, err := ParseProcNetTCP("h\n 0: ZZ:0016 0:0 0A a b c d e 1\n", false); err == nil {
		t.Error("expected an error on a malformed address")
	}
}

func TestParseCgroup(t *testing.T) {
	cases := []struct{ in, unit, container, pod string }{
		{"0::/system.slice/ssh.service\n", "ssh.service", "", ""},
		{"0::/system.slice/docker-" + strings.Repeat("ab", 32) + ".scope\n", "", strings.Repeat("ab", 32), ""},
		{"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1a2b3c4d_0000_1111_2222_333344445555.slice/cri-containerd-" +
			strings.Repeat("cd", 32) + ".scope\n", "", strings.Repeat("cd", 32), "1a2b3c4d-0000-1111-2222-333344445555"},
		{"12:pids:/user.slice/user-0.slice/session-3.scope\n", "", "", ""},
	}
	for _, c := range cases {
		u, ct, p := ParseCgroup(c.in)
		if u != c.unit || ct != c.container || p != c.pod {
			t.Errorf("ParseCgroup(%q) = %q %q %q", c.in, u, ct, p)
		}
	}
}

func TestDockerHelpers(t *testing.T) {
	if got := PublishedHostPorts("0.0.0.0:5000->5000/tcp, :::5000->5000/tcp, 3306/tcp, 127.0.0.1:9000-9001->9000-9001/tcp"); !reflect.DeepEqual(got, []int{5000, 9000, 9001}) {
		t.Errorf("PublishedHostPorts = %v", got)
	}
	args := []string{"/usr/bin/docker-proxy", "-proto", "tcp", "-host-ip", "0.0.0.0", "-host-port", "5000", "-container-ip", "172.17.0.2", "-container-port", "5000"}
	if got := dockerProxyTarget(args); got != "172.17.0.2:5000" {
		t.Errorf("dockerProxyTarget = %q", got)
	}
}

func TestRedactCmdline(t *testing.T) {
	got := RedactCmdline([]string{"redis-server", "--requirepass", "hunter2", "--port", "6379", "--api-key=abc"})
	if strings.Contains(got, "hunter2") || strings.Contains(got, "abc") || !strings.Contains(got, "--port 6379") {
		t.Errorf("RedactCmdline = %q", got)
	}
}

func TestParseKubeServices(t *testing.T) {
	out := "kube-system/traefik\tLoadBalancer\t80:30080,443:30443,\ndefault/web\tClusterIP\t80:,\ndefault/np\tNodePort\t8080:31000,\n"
	got := ParseKubeServices(out)
	want := []KubeService{
		{Name: "kube-system/traefik", Type: "LoadBalancer", Port: 80, NodePort: 30080},
		{Name: "kube-system/traefik", Type: "LoadBalancer", Port: 443, NodePort: 30443},
		{Name: "default/np", Type: "NodePort", Port: 8080, NodePort: 31000},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseKubeServices = %+v", got)
	}
}

func TestWriteLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inv.json")
	inv := Inventory{Format: Format, Hostname: "h", Listeners: []Listener{{Address: "0.0.0.0", Port: 22, Owner: &Owner{PID: 1, Process: "sshd"}}}}
	if err := inv.Write(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got.Listeners[0].Owner.Process != "sshd" {
		t.Fatalf("Load = %+v, %v", got, err)
	}
}
