// internal/ports/top_ports.go
package ports

// TopPortsList contient les ports les plus fréquents ordonnés par popularité.
var TopPortsList = []int{
	80, 23, 22, 443, 21, 110, 993, 143, 3389, 8080, 8443, 53, 139, 445, 25,
	587, 111, 2049, 3306, 5432, 27017, 6379, 11211, 5900, 8000, 8888, 1723,
	49152, 49153, 49154, 8081, 161, 5000, 5001, 8008, 9000, 9090, 995, 1025,
	1026, 1027, 1028, 1029, 1433, 1521, 2000, 2082, 2083, 2086, 2087, 3000,
	3128, 5060, 5222, 5901, 8088, 8181, 9080, 10000,
}

// GetTopPorts retourne les N ports les plus populaires.
func GetTopPorts(n int) []int {
	if n <= 0 {
		n = 100
	}
	if n > len(TopPortsList) {
		n = len(TopPortsList)
	}
	res := make([]int, n)
	copy(res, TopPortsList[:n])
	return res
}