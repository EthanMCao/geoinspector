package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/censoredplanet/geoinspector/config"
	"github.com/censoredplanet/geoinspector/dns"
	"github.com/censoredplanet/geoinspector/tcp"
	"github.com/censoredplanet/geoinspector/util"
)

var Empty struct{}

func ProcessInputURLs(file *os.File) []*util.InputURL {
	scanner := bufio.NewScanner(file)
	var inputURLs []*util.InputURL
	for scanner.Scan() {
		fullURL := scanner.Text()
		u, err := url.Parse(fullURL)
		if err != nil {
			log.Println("[MAIN.ProcessInputURLs] WARNING: Could not parse: ", fullURL)
			continue
		}
		inputURLs = append(inputURLs, &util.InputURL{
			URL:    fullURL,
			Domain: u.Hostname(),
		})
	}
	return inputURLs
}

func ProcessInputDNSResolvers(file *os.File) []*dns.InputDNSResolver {
	scanner := bufio.NewScanner(file)
	var inputDNSResolvers []*dns.InputDNSResolver
	for scanner.Scan() {
		line := scanner.Text()
		data := strings.Split(line, ",")
		if len(data) != 4 {
			log.Println("[MAIN.ProcessInputDNSResolvers] WARNING : Input DNS resolvers file does not have the right data")
			continue
		}
		inputDNSResolvers = append(inputDNSResolvers, &dns.InputDNSResolver{
			IP:      data[0],
			Name:    data[1],
			Country: data[2],
			Kind:    data[3],
		})
	}
	return inputDNSResolvers
}

func ProcessInputServers(file *os.File) []*tcp.InputServer {
	scanner := bufio.NewScanner(file)
	var InputServers []*tcp.InputServer
	for scanner.Scan() {
		line := scanner.Text()
		data := strings.Split(line, ",")
		if len(data) != 3 {
			log.Println("[MAIN.ProcessInputServers] WARNING : Input conn file does not have the right data")
			continue
		}
		InputServers = append(InputServers, &tcp.InputServer{
			Domain:  data[0],
			Ip:      data[1],
			Country: data[2],
		})
	}
	return InputServers
}

func DnsModule() {
	inputURLFile, err := os.Open(config.InputURLFile)
	if err != nil {
		log.Fatal("[MAIN.DnsModule] Could not open input URL File: ", err)
	}
	defer inputURLFile.Close()
	inputURLs := ProcessInputURLs(inputURLFile)
	inputDNSResolversFile, err := os.Open(config.InputDNSResolversFile)
	if err != nil {
		log.Fatal("[MAIN.DnsModule] Could not open input DNS resolvers File: ", err)
	}
	defer inputDNSResolversFile.Close()
	inputDNSResolvers := ProcessInputDNSResolvers(inputDNSResolversFile)
	log.Println("[MAIN.DnsModule] Staring DNS query phase")
	dns.DNS(inputDNSResolvers, inputURLs)
}

func TCPModule(inputFile string) {
	inputServersFile, err := os.Open(inputFile)
	if err != nil {
		log.Fatal("[MAIN.TCPModule] Could not open input conn servers File: ", err)
	}
	defer inputServersFile.Close()
	inputServers := ProcessInputServers(inputServersFile)
	log.Println("[MAIN.TCPModule] Starting TCP, TLS and HTTP phase")
	tcp.ConnSendRecv(inputServers, 443, config.NumRedirects)
}

func ExtractDNSData(filename string, controlFilename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal("[MAIN.ExtractDNSData] Could not open DNS input file: ", err)
	}
	outputFile, err := os.OpenFile(config.DNSParsedOutput, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		log.Fatal("[MAIN.ExtractDNSData] Could not open DNS output file: ", err)
	}
	domainNumIps := make(map[string]int)
	scanner := bufio.NewScanner(file)
	entries := make(map[string]struct{})
	for scanner.Scan() {
		var data dns.QueryResponse
		if err := json.Unmarshal(scanner.Bytes(), &data); err != nil {
			log.Fatal("[MAIN.ExtractDNSData] Could not unmarshal json: ", err)
		}
		domain := data.Domain
		if _, ok := domainNumIps[domain]; !ok {
			domainNumIps[domain] = 0
		}
		for _, response := range data.Responses {
			if response.Rcode == 0 && response.Err == "null" {
				for _, resolvedIP := range response.Response {
					if resolvedIP.Type == "A" {
						if _, ok := entries[domain+resolvedIP.Data]; !ok {
							outputFile.Write([]byte(fmt.Sprintf("%s,%s,%s\n", domain, resolvedIP.Data, "TODO")))
							entries[domain+resolvedIP.Data] = Empty
							domainNumIps[domain] += 1
						}
					}
				}
			}
		}
	}
	// For domains that did not have any resolved IPs
	// add IPs from the control file when available
	if controlFilename != "" {
		if controlFile, err := os.Open(controlFilename); err == nil {
			controlScanner := bufio.NewScanner(controlFile)
			for controlScanner.Scan() {
				// Each line contains domain,IP,ASN
				domainIpAsn := controlScanner.Text()
				domainIpAsnSplit := strings.Split(domainIpAsn, ",")
				domain := domainIpAsnSplit[0]
				if num, ok := domainNumIps[domain]; ok && num == 0 {
					// No IPs for this domain in original output, add control IP
					outputFile.Write([]byte(fmt.Sprintf("%s\n", domainIpAsn)))
				}
			}
		}
	}

}

func setupOutputDir() {
	if config.OutputDir == "" {
		timestamp := time.Now().Format("2006-01-02_15-04-05")
		config.OutputDir = filepath.Join("results", timestamp)
	}
	log.Printf("[MAIN.setupOutputDir] Output directory: %s", config.OutputDir)

	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		log.Fatal("[MAIN.setupOutputDir] Could not create output directory: ", err)
	}

	prependDir := func(path string, defaultBase string) string {
		if path == "-" || path == "" {
			return filepath.Join(config.OutputDir, defaultBase)
		}
		return filepath.Join(config.OutputDir, filepath.Base(path))
	}

	config.OutputDNSFile = prependDir(config.OutputDNSFile, "dns_output.json")
	config.DNSParsedOutput = prependDir(config.DNSParsedOutput, "dns_parsed_output.csv")
	config.OutputConnFile = prependDir(config.OutputConnFile, "tcp_output.json")
	config.OutputFailedConnFile = prependDir(config.OutputFailedConnFile, "tcp_failed.csv")
}

func main() {
	log.Println("[MAIN.main] Staring GeoInspector measurements")
	setupOutputDir()
	switch config.Module {
	case "full":
		DnsModule()
		ExtractDNSData(config.OutputDNSFile, config.ControlDNSFile)
		TCPModule(config.DNSParsedOutput)
	case "dns":
		DnsModule()
	case "tcp":
		TCPModule(config.InputConnFile)
	}
	log.Println("[MAIN.main] Finished GeoInspector measurements")
}
