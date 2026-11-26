package ports

// TopPortsList is the order --top-ports N takes ports in. It is tcpcat's own
// list, ordered by what matters for exposure rather than copied from another
// scanner's frequency table:
//
//  1. the ports most often found open on the internet (web, remote access,
//     mail, file sharing, the common databases);
//  2. every TCP port tcpcat's AI dictionary knows (internal/ai/kb): the
//     services whose exposure it can judge, from etcd and the kubelet to
//     Minecraft and Modbus. A test there keeps the two in step;
//  3. other well-known service ports above 1024 (alternate web ports, admin
//     panels, brokers, game and media servers, IoT);
//  4. the rest of the system ports, 1 to 1024.
//
// That is 1,361 ports, so --top-ports 1000 is a real thousand.
var TopPortsList = buildTopPorts()

var commonOpen = []int{
	80, 23, 22, 443, 21, 110, 993, 143, 3389, 8080, 8443, 53, 139, 445, 25,
	587, 111, 2049, 3306, 5432, 27017, 6379, 11211, 5900, 8000, 8888, 1723,
	49152, 49153, 49154, 8081, 161, 5000, 5001, 8008, 9000, 9090, 995, 1025,
	1026, 1027, 1028, 1029, 1433, 1521, 2000, 2082, 2083, 2086, 2087, 3000,
	3128, 5060, 5222, 5901, 8088, 8181, 9080, 10000,
}

// dictionaryPorts are the TCP ports of internal/ai/kb/services.yaml.
var dictionaryPorts = []int{
	21, 22, 23, 25, 53, 80, 102, 110, 111, 135, 139, 143, 443, 445, 465, 502,
	554, 587, 623, 631, 873, 993, 995, 1080, 1194, 1433, 1521, 1883, 1911,
	2022, 2049, 2181, 2222, 2323, 2375, 2376, 2379, 2380, 2404, 2455, 3000,
	3128, 3306, 3389, 4222, 4646, 4840, 4911, 5001, 5060, 5061, 5432, 5601,
	5672, 5800, 5900, 5901, 5984, 5985, 5986, 6000, 6001, 6379, 6443, 7000,
	7474, 7687, 8000, 8008, 8080, 8081, 8086, 8123, 8200, 8300, 8301, 8443,
	8500, 8554, 8883, 8888, 9000, 9001, 9042, 9090, 9092, 9093, 9100, 9200,
	9300, 9443, 9600, 10000, 10250, 10255, 10256, 10257, 10259, 11211, 11434,
	15672, 20000, 25565, 25575, 27017, 27018, 34962, 34964, 44818, 47808,
}

var wellKnownHigh = []int{
	// alternate web ports and admin panels
	1081, 2052, 2053, 2095, 2096, 3001, 3002, 3030, 3333, 4000, 4001, 4040,
	4200, 4243, 4443, 4444, 4567, 4711, 4712, 4848, 5050, 5080, 5443, 5555,
	5800, 5985, 6080, 6443, 6543, 7001, 7002, 7070, 7071, 7080, 7443, 7777,
	7778, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8009, 8010, 8020, 8042,
	8069, 8082, 8083, 8084, 8085, 8086, 8087, 8089, 8090, 8091, 8092, 8093,
	8094, 8095, 8096, 8097, 8098, 8099, 8100, 8118, 8139, 8140, 8161, 8180,
	8222, 8243, 8280, 8281, 8333, 8400, 8444, 8445, 8530, 8531, 8600, 8800,
	8834, 8880, 8881, 8887, 8889, 8983, 8989, 9002, 9003, 9009, 9010, 9043,
	9060, 9081, 9091, 9099, 9191, 9292, 9393, 9418, 9444, 9800, 9876, 9943,
	9980, 9981, 9990, 9999, 10001, 10443, 12443, 16080, 18080, 18443, 19999,
	20080, 28080, 30000, 32400, 50000,
	// databases, caches, brokers, search
	1434, 1830, 2483, 2484, 3050, 3307, 3351, 4369, 5433, 5984, 5986, 6380,
	6381, 7199, 7473, 8529, 9160, 9500, 11214, 11215, 16379, 26379, 28015,
	28017, 29015, 61613, 61614, 61616, 1414, 5671, 9094, 9095,
	// infrastructure, orchestration, monitoring
	2377, 2379, 4194, 4243, 4505, 4506, 6783, 7946, 8285, 8472, 9100, 9101,
	9102, 9103, 9115, 9187, 9273, 9411, 9779, 10050, 10051, 10248, 10249,
	16443, 19100, 19531, 30001,
	// remote access, VPN, voice and video, files
	1194, 1701, 1723, 2200, 2202, 2223, 3260, 3478, 3689, 3690, 4899, 5222,
	5269, 5631, 5632, 5938, 6129, 6568, 7547, 8291, 8728, 8729, 10022, 12345,
	1935, 5004, 5005, 5353, 7676, 8554, 9554, 37777, 34567,
	// game servers
	2302, 3074, 3724, 6112, 7778, 9987, 25564, 25566, 25567, 27005, 27015,
	27016, 28960, 30120, 64738,
	// windows, directory, mail
	1801, 2103, 2105, 2107, 2525, 3268, 3269, 3343, 47001, 49155, 49156,
	49157, 5357, 9389,
}

func buildTopPorts() []int {
	seen := make(map[int]bool, 1300)
	out := make([]int, 0, 1300)
	add := func(ps ...int) {
		for _, p := range ps {
			if p >= 1 && p <= 65535 && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	add(commonOpen...)
	add(dictionaryPorts...)
	add(wellKnownHigh...)
	for p := 1; p <= 1024; p++ {
		add(p)
	}
	return out
}

// GetTopPorts returns the first n ports of TopPortsList (100 when n <= 0, the
// whole list when n is larger).
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
