package service

import "testing"

func TestMatchBannerSignature(t *testing.T) {
	tests := []struct {
		name        string
		banner      string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{"openssh with version", "SSH-2.0-OpenSSH_9.6p1 Ubuntu", "openssh", "9.6p1", true},
		{"vsftpd", "220 (vsFTPd 3.0.5)", "vsftpd", "3.0.5", true},
		{"proftpd", "220 ProFTPD 1.3.5 Server ready.", "proftpd", "1.3.5", true},
		{"pure-ftpd no version", "220---------- Welcome to Pure-FTPd ----------", "pure-ftpd", "", true},
		{"postfix no version", "220 mail.example.com ESMTP Postfix", "postfix", "", true},
		{"exim with version", "220 mx ESMTP Exim 4.94.2 Ubuntu", "exim", "4.94.2", true},
		{"dovecot", "* OK IMAP4rev1 Dovecot ready", "dovecot", "", true},
		{"nginx", "Server: nginx/1.24.0", "nginx", "1.24.0", true},
		{"apache", "Server: Apache/2.4.41 (Ubuntu)", "apache", "2.4.41", true},
		{"iis", "Server: Microsoft-IIS/10.0", "iis", "10.0", true},
		{"mariadb", "5.5.5-10.6.12-MariaDB", "mariadb", "10.6.12", true},
		{"mariadb with distro suffix", "5.5.5-10.6.12-MariaDB-1:10.6.12+maria~ubu2004-log", "mariadb", "10.6.12", true},
		{"elasticsearch", `{"name":"n","version":{"number":"8.11.1"}}`, "elasticsearch", "8.11.1", true},
		{"unrecognised", "220 generic ftp ready", "", "", false},
		{"empty", "", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, version, _, _, ok := matchBannerSignature(tt.banner)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (name=%q version=%q)", ok, tt.wantOK, name, version)
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

// A generic FTP/SMTP banner must NOT match a named-product signature, so
// the caller's generic fallback still applies -- guarding against a loose
// pattern swallowing every banner.
func TestMatchBannerSignatureNoFalsePositive(t *testing.T) {
	for _, banner := range []string{
		"220 Service ready",
		"+OK POP3 ready",
		"HTTP/1.1 200 OK",
	} {
		if name, _, _, _, ok := matchBannerSignature(banner); ok {
			t.Errorf("banner %q matched %q, want no match", banner, name)
		}
	}
}
