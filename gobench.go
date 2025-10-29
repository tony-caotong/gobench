package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"crypto/tls"
	"strings"
	"encoding/binary"
	"encoding/hex"

	"github.com/valyala/fasthttp"
)

const (
	PP2_SIGNATURE = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
	PP2_VERSION = 0x20
	PP2_CMD_LOCAL byte = 0x00
	PP2_CMD_PROXY byte = 0x01
	PP2_AF_UNSPEC byte = 0x00
	PP2_AF_INET byte = 0x10      // IPv4
	PP2_AF_INET6 byte = 0x20     // IPv6
	PP2_AF_UNIX byte = 0x30      // Unix
	PP2_TRANS_UNSPEC byte = 0x00
	PP2_TRANS_STREAM byte = 0x01 // TCP
	PP2_TRANS_DGRAM byte = 0x02  // UDP	
)

var (
	requests         int64
	period           int64
	clients          int
	url              string
	urlsFilePath     string
	keepAlive        bool
	postDataFilePath string
	writeTimeout     int
	readTimeout      int
	authHeader       string
	insecSkip        bool
	sessionTicket    bool
	sessionCache     bool
	tlsVersion       int
	proxyProtocolVersion int
	proxyProtocolSrcIP string
	proxyProtocolSrcPort int
	proxyProtocolDstIP string
	proxyProtocolDstPort int
	proxyProtocolV2Command string
	proxyProtocolV2Transport string
	proxyProtocolV2TLV string
	debug bool
)

type Configuration struct {
	urls       []string
	method     string
	postData   []byte
	requests   int64
	period     int64
	keepAlive  bool
	authHeader string

	myClient fasthttp.Client
}

type Result struct {
	requests      int64
	success       int64
	networkFailed int64
	badFailed     int64
}

var readThroughput int64
var writeThroughput int64

type MyConn struct {
	net.Conn
}

func (this *MyConn) Read(b []byte) (n int, err error) {
	len, err := this.Conn.Read(b)

	if err == nil {
		atomic.AddInt64(&readThroughput, int64(len))
	}

	return len, err
}

func (this *MyConn) Write(b []byte) (n int, err error) {
	len, err := this.Conn.Write(b)

	if err == nil {
		atomic.AddInt64(&writeThroughput, int64(len))
	}

	return len, err
}

func (this *MyConn) writeProxyProtocolV1(srcIP, dstIP string, srcPort, dstPort int) error {
	var protocol string
	if net.ParseIP(srcIP).To4() != nil && net.ParseIP(dstIP).To4() != nil {
		protocol = "TCP4"
	} else {
		protocol = "TCP6"
	}

	header := fmt.Sprintf("PROXY %s %s %s %d %d\r\n", protocol, srcIP, dstIP, srcPort, dstPort)
	_, err := this.Write([]byte(header))
	return err
}

func (this *MyConn) writeProxyProtocolV2(srcIP, dstIP string, srcPort, dstPort int) error {
	conn := this.Conn
	var header []byte
	var familyProtocol byte
	var addrData []byte
    
	signature := []byte(PP2_SIGNATURE)
    
	var cmd byte
	switch strings.ToUpper(proxyProtocolV2Command) {
	case "LOCAL":
		cmd = PP2_CMD_LOCAL
	default:
		cmd = PP2_CMD_PROXY
	}

	versionCmd := PP2_VERSION | cmd

	if cmd == PP2_CMD_LOCAL {
		header = make([]byte, len(signature)+1)
		copy(header, signature)
		header[len(signature)] = versionCmd
	} else {
		srcIPParsed := net.ParseIP(srcIP)
		dstIPParsed := net.ParseIP(dstIP)

		if srcIPParsed == nil || dstIPParsed == nil {
			return fmt.Errorf("invalid IP address: src=%s, dst=%s", srcIP, dstIP)
		}

		trans := PP2_TRANS_STREAM
		if strings.ToUpper(proxyProtocolV2Transport) == "DGRAM" {
			trans = PP2_TRANS_DGRAM
		}
		
		if srcIPParsed.To4() != nil && dstIPParsed.To4() != nil {
			familyProtocol = PP2_AF_INET | trans
			addrData = make([]byte, 12)
			copy(addrData[0:4], srcIPParsed.To4())
			copy(addrData[4:8], dstIPParsed.To4())
			binary.BigEndian.PutUint16(addrData[8:10], uint16(srcPort))
			binary.BigEndian.PutUint16(addrData[10:12], uint16(dstPort))
		} else {
			familyProtocol = PP2_AF_INET6 | trans
			addrData = make([]byte, 36)
			copy(addrData[0:16], srcIPParsed.To16())
			copy(addrData[16:32], dstIPParsed.To16())
			binary.BigEndian.PutUint16(addrData[32:34], uint16(srcPort))
			binary.BigEndian.PutUint16(addrData[34:36], uint16(dstPort))
		}

		addrLen := len(addrData)
		tlvLen := 0
		var tlvBytes []byte

		if proxyProtocolV2TLV != "" {
			var err error
			tlvBytes, err = hex.DecodeString(proxyProtocolV2TLV)
			if err != nil {
				return fmt.Errorf("invalid TLV data: %v", err)
			}
			tlvLen = len(tlvBytes)
		}
		
		totalLen := uint16(addrLen + tlvLen)
		header = make([]byte, len(signature)+4+addrLen+tlvLen)
		pos := 0

		copy(header[pos:], signature)
		pos += len(signature)

		header[pos] = versionCmd
		pos++

		header[pos] = familyProtocol
		pos++

		binary.BigEndian.PutUint16(header[pos:pos+2], totalLen)
		pos += 2

		copy(header[pos:], addrData)
		pos += addrLen

		if tlvLen > 0 {
			copy(header[pos:], tlvBytes)
		}

		if debug {
			fmt.Printf("Proxy Protocol v2 header (%d bytes):\n", len(header))
			fmt.Printf("  Signature: ")
			for i := 0; i < 12; i++ {
				fmt.Printf("%02x ", header[i])
			}
			fmt.Printf("\n")
			fmt.Printf("  Version/Command: 0x%02x\n", header[12])
			fmt.Printf("  Family/Protocol: 0x%02x\n", header[13])
			fmt.Printf("  Length: %d\n", binary.BigEndian.Uint16(header[14:16]))
            
			if addrLen > 0 {
				fmt.Printf("  Address data: ")
				for i := 16; i < 16+addrLen && i < len(header); i++ {
					fmt.Printf("%02x ", header[i])
				}
				fmt.Printf("\n")
			}
		}
	}

	_, err := conn.Write(header)
	return err
}

func init() {
	flag.Int64Var(&requests, "r", -1, "Number of requests per client")
	flag.IntVar(&clients, "c", 100, "Number of concurrent clients")
	flag.StringVar(&url, "u", "", "URL")
	flag.StringVar(&urlsFilePath, "f", "", "URL's file path (line seperated)")
	flag.BoolVar(&keepAlive, "k", false, "Do HTTP keep-alive")
	flag.StringVar(&postDataFilePath, "d", "", "HTTP POST data file path")
	flag.Int64Var(&period, "t", -1, "Period of time (in seconds)")
	flag.IntVar(&writeTimeout, "tw", 5000, "Write timeout (in milliseconds)")
	flag.IntVar(&readTimeout, "tr", 5000, "Read timeout (in milliseconds)")
	flag.StringVar(&authHeader, "auth", "", "Authorization header")
	flag.BoolVar(&insecSkip, "tls_skip", false, "if skip insecure verify when tls.")
	flag.BoolVar(&sessionTicket, "tls_ticket", true, "if use tls session ticket.")
	flag.BoolVar(&sessionCache, "tls_cache", true, "if use tls session cache.")
	flag.IntVar(&tlsVersion, "ver", 0, "Version of tls: 10/11/12/13. ")
	flag.IntVar(&proxyProtocolVersion, "proxy-protocol-version", 0, "Proxy Protocol version: 0(off), 1 or 2")
	flag.StringVar(&proxyProtocolSrcIP, "proxy-protocol-src-ip", "", "Source IP for Proxy Protocol")
	flag.IntVar(&proxyProtocolSrcPort, "proxy-protocol-src-port", 0, "Source port for Proxy Protocol")
	flag.StringVar(&proxyProtocolDstIP, "proxy-protocol-dst-ip", "", "Destination IP for Proxy Protocol")
	flag.IntVar(&proxyProtocolDstPort, "proxy-protocol-dst-port", 0, "Destination port for Proxy Protocol")
	flag.StringVar(&proxyProtocolV2Command, "proxy-protocol-v2-command", "PROXY", "Proxy Protocol v2 command (PROXY or LOCAL)")
	flag.StringVar(&proxyProtocolV2Transport, "proxy-protocol-v2-transport", "STREAM", "Proxy Protocol v2 transport (STREAM or DGRAM)")
	flag.StringVar(&proxyProtocolV2TLV, "proxy-protocol-v2-tlv", "", "Proxy Protocol v2 TLV data in hex format")
	flag.BoolVar(&debug, "debug", false, "print debug info")	
}

func printResults(results map[int]*Result, startTime time.Time) {
	var requests int64
	var success int64
	var networkFailed int64
	var badFailed int64

	for _, result := range results {
		requests += result.requests
		success += result.success
		networkFailed += result.networkFailed
		badFailed += result.badFailed
	}

	elapsed := int64(time.Since(startTime).Seconds())

	if elapsed == 0 {
		elapsed = 1
	}

	fmt.Println()
	fmt.Printf("Requests:                       %10d hits\n", requests)
	fmt.Printf("Successful requests:            %10d hits\n", success)
	fmt.Printf("Network failed:                 %10d hits\n", networkFailed)
	fmt.Printf("Bad requests failed (!2xx):     %10d hits\n", badFailed)
	fmt.Printf("Successful requests rate:       %10d hits/sec\n", success/elapsed)
	fmt.Printf("Read throughput:                %10d bytes/sec\n", readThroughput/elapsed)
	fmt.Printf("Write throughput:               %10d bytes/sec\n", writeThroughput/elapsed)
	fmt.Printf("Test time:                      %10d sec\n", elapsed)
}

func readLines(path string) (lines []string, err error) {

	var file *os.File
	var part []byte
	var prefix bool

	if file, err = os.Open(path); err != nil {
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	buffer := bytes.NewBuffer(make([]byte, 0))
	for {
		if part, prefix, err = reader.ReadLine(); err != nil {
			break
		}
		buffer.Write(part)
		if !prefix {
			lines = append(lines, buffer.String())
			buffer.Reset()
		}
	}
	if err == io.EOF {
		err = nil
	}
	return
}

type fakeSessionCache struct{}

func (fakeSessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	return nil, false
}

func (fakeSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	// no-op
}

func NewConfiguration() *Configuration {

	if urlsFilePath == "" && url == "" {
		flag.Usage()
		os.Exit(1)
	}

	if requests == -1 && period == -1 {
		fmt.Println("Requests or period must be provided")
		flag.Usage()
		os.Exit(1)
	}

	if requests != -1 && period != -1 {
		fmt.Println("Only one should be provided: [requests|period]")
		flag.Usage()
		os.Exit(1)
	}

	configuration := &Configuration{
		urls:       make([]string, 0),
		method:     "GET",
		postData:   nil,
		keepAlive:  keepAlive,
		requests:   int64((1 << 63) - 1),
		authHeader: authHeader}

	if period != -1 {
		configuration.period = period

		timeout := make(chan bool, 1)
		go func() {
			<-time.After(time.Duration(period) * time.Second)
			timeout <- true
		}()

		go func() {
			<-timeout
			pid := os.Getpid()
			proc, _ := os.FindProcess(pid)
			err := proc.Signal(os.Interrupt)
			if err != nil {
				log.Println(err)
				return
			}
		}()
	}

	if requests != -1 {
		configuration.requests = requests
	}

	if urlsFilePath != "" {
		fileLines, err := readLines(urlsFilePath)

		if err != nil {
			log.Fatalf("Error in ioutil.ReadFile for file: %s Error: ", urlsFilePath, err)
		}

		configuration.urls = fileLines
	}

	if url != "" {
		configuration.urls = append(configuration.urls, url)
	}

	if postDataFilePath != "" {
		configuration.method = "POST"

		data, err := ioutil.ReadFile(postDataFilePath)

		if err != nil {
			log.Fatalf("Error in ioutil.ReadFile for file path: %s Error: ", postDataFilePath, err)
		}

		configuration.postData = data
	}

	configuration.myClient.ReadTimeout = time.Duration(readTimeout) * time.Millisecond
	configuration.myClient.WriteTimeout = time.Duration(writeTimeout) * time.Millisecond
	configuration.myClient.MaxConnsPerHost = clients

	configuration.myClient.Dial = MyDialer()
	configuration.myClient.TLSConfig = &tls.Config{}
	configuration.myClient.TLSConfig.InsecureSkipVerify = insecSkip
	/* It's a bug in library fasthttp, when sessiontick is disabled, 
	   sessionCache is also disabled. */
	configuration.myClient.TLSConfig.SessionTicketsDisabled = !sessionTicket
	if sessionCache == false {
		configuration.myClient.TLSConfig.ClientSessionCache = fakeSessionCache{}
	}
	switch tlsVersion {
	case 10:
		configuration.myClient.TLSConfig.MinVersion = tls.VersionTLS10
		configuration.myClient.TLSConfig.MaxVersion = tls.VersionTLS10
	case 11:
		configuration.myClient.TLSConfig.MinVersion = tls.VersionTLS11
		configuration.myClient.TLSConfig.MaxVersion = tls.VersionTLS11
	case 12:
		configuration.myClient.TLSConfig.MinVersion = tls.VersionTLS12
		configuration.myClient.TLSConfig.MaxVersion = tls.VersionTLS12
	case 13:
		configuration.myClient.TLSConfig.MinVersion = tls.VersionTLS13
		configuration.myClient.TLSConfig.MaxVersion = tls.VersionTLS13
	}

	return configuration
}

func MyDialer() func(address string) (conn net.Conn, err error) {
	return func(address string) (net.Conn, error) {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			return nil, err
		}

		myConn := &MyConn{Conn: conn}
		conn = myConn.Conn;
		if proxyProtocolVersion > 0 {
			localAddr := conn.LocalAddr().(*net.TCPAddr)
			remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

			srcIP := proxyProtocolSrcIP
			if srcIP == "" {
				srcIP = localAddr.IP.String()
			}
			dstIP := proxyProtocolDstIP
			if dstIP == "" {
				dstIP = remoteAddr.IP.String()
			}
			srcPort := proxyProtocolSrcPort
			if srcPort == 0 {
				srcPort = localAddr.Port
			}
			dstPort := proxyProtocolDstPort
			if dstPort == 0 {
				dstPort = remoteAddr.Port
			}

			if proxyProtocolVersion == 2 {
				err = myConn.writeProxyProtocolV2(srcIP, dstIP, srcPort, dstPort)
			} else {
				err = myConn.writeProxyProtocolV1(srcIP, dstIP, srcPort, dstPort)
			}
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to write proxy protocol header: %v", err)
			}
		}

		return myConn, nil
	}
}

func client(configuration *Configuration, result *Result, done *sync.WaitGroup) {
	for result.requests < configuration.requests {
		for _, tmpUrl := range configuration.urls {

			req := fasthttp.AcquireRequest()

			req.SetRequestURI(tmpUrl)
			req.Header.SetMethodBytes([]byte(configuration.method))

			if configuration.keepAlive == true {
				req.Header.Set("Connection", "keep-alive")
			} else {
				req.Header.Set("Connection", "close")
			}

			if len(configuration.authHeader) > 0 {
				req.Header.Set("Authorization", configuration.authHeader)
			}

			req.SetBody(configuration.postData)

			resp := fasthttp.AcquireResponse()
			err := configuration.myClient.Do(req, resp)
			statusCode := resp.StatusCode()
			result.requests++
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)

			if err != nil {
				result.networkFailed++
				continue
			}

			if statusCode == fasthttp.StatusOK {
				result.success++
			} else {
				result.badFailed++
			}
		}
	}

	done.Done()
}

func main() {

	startTime := time.Now()
	var done sync.WaitGroup
	results := make(map[int]*Result)

	signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt)
	go func() {
		_ = <-signalChannel
		printResults(results, startTime)
		os.Exit(0)
	}()

	flag.Parse()

	configuration := NewConfiguration()

	goMaxProcs := os.Getenv("GOMAXPROCS")

	if goMaxProcs == "" {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	fmt.Printf("Dispatching %d clients\n", clients)

	done.Add(clients)
	for i := 0; i < clients; i++ {
		result := &Result{}
		results[i] = result
		go client(configuration, result, &done)

	}
	fmt.Println("Waiting for results...")
	done.Wait()
	printResults(results, startTime)
}
