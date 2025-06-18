package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type AccessLogEntry struct {
	Timestamp    time.Time              `json:"timestamp"`
	RemoteAddr   string                 `json:"remote_addr"`
	Method       string                 `json:"method"`
	URI          string                 `json:"uri"`
	Protocol     string                 `json:"protocol"`
	Status       int                    `json:"status"`
	BytesSent    int64                  `json:"bytes_sent"`
	Referer      string                 `json:"referer,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	RequestTime  float64                `json:"request_time,omitempty"`
	UpstreamTime float64                `json:"upstream_time,omitempty"`
	RequestID    string                 `json:"request_id,omitempty"`
	Context      map[string]interface{} `json:"context,omitempty"`
}

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[37m"
	ColorBold   = "\033[1m"
	ColorDim    = "\033[2m"
)

var (
	groupBy     = flag.String("group-by", "", "Group results by: status, method, uri, ip, hour, user")
	outputJSON  = flag.Bool("json", false, "Output in JSON format")
	summary     = flag.Bool("summary", false, "Show summary statistics")
	since       = flag.String("since", "", "Show logs since date (YYYY-MM-DD or YYYY-MM-DD HH:MM)")
	until       = flag.String("until", "", "Show logs until date (YYYY-MM-DD or YYYY-MM-DD HH:MM)")
	search      = flag.String("search", "", "Search for specific text in URIs")
	noColor     = flag.Bool("no-color", false, "Disable colored output")
	compact     = flag.Bool("compact", false, "Compact output format")
	stats       = flag.Bool("stats", false, "Show detailed statistics")
	lastN       = flag.Int("last", 0, "Show last N entries")
	remotePath  = flag.String("remote-path", "/var/log/nginx/access.log", "Remote log file path")
	sshConfig   = flag.String("ssh-config", "", "Path to SSH config file (default: ~/.ssh/config)")
	report      = flag.Bool("report", false, "Generate comprehensive analysis report")
	follow      = flag.Bool("follow", false, "Follow log file for new entries (local files only)")
	export      = flag.String("export", "", "Export filtered results to file (csv, json)")
	geoIP       = flag.Bool("geoip", false, "Include GeoIP information for IPs (requires geoip database)")
	debug       = flag.Bool("debug", false, "Enable debug output to see log parsing details")
	showSamples = flag.Bool("show-samples", false, "Show sample log lines to help debug format issues")

	statusFilter = flag.String("status", "", "Filter by HTTP status code (e.g., 200, 404, 4xx, 5xx)")
	methodFilter = flag.String("method", "", "Filter by HTTP method (GET, POST, etc.)")
	ipFilter     = flag.String("ip", "", "Filter by IP address or CIDR block")
	userFilter   = flag.String("user", "", "Filter by user ID")
	slowOnly     = flag.Bool("slow-only", false, "Show only slow requests (>1s)")
	minTime      = flag.Float64("min-time", 0, "Minimum request time in seconds")
	maxTime      = flag.Float64("max-time", 0, "Maximum request time in seconds")
	minBytes     = flag.Int64("min-bytes", 0, "Minimum response size in bytes")
	excludeBots  = flag.Bool("exclude-bots", false, "Exclude common bot traffic")
	errorsOnly   = flag.Bool("errors-only", false, "Show only 4xx and 5xx responses")
	pathFilter   = flag.String("path", "", "Filter by URL path (supports wildcards)")
	topN         = flag.Int("top", 10, "Show top N results in summaries")
)

func main() {
	// Parse all arguments to handle flags anywhere in the command line
	args := os.Args[1:]
	var target string
	var flagArgs []string

	// Separate the target (non-flag argument) from flag arguments
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
		} else if !strings.HasPrefix(arg, "-") && target == "" {
			target = arg
		} else {
			flagArgs = append(flagArgs, arg) // Additional arguments after target
		}
	}

	// Temporarily replace os.Args to only include flag arguments for parsing
	originalArgs := os.Args
	os.Args = append([]string{os.Args[0]}, flagArgs...)
	flag.Parse()
	os.Args = originalArgs // Restore original args

	if target == "" {
		printUsage()
		os.Exit(1)
	}

	if *follow && !isRemoteTarget(target) {
		followLogFile(target)
		return
	}

	var entries []AccessLogEntry
	var err error

	if isRemoteTarget(target) {
		fmt.Printf("%s%sConnecting to %s...%s\n", ColorDim, ColorCyan, target, ColorReset)
		entries, err = parseRemoteLogFile(target)
	} else {
		entries, err = parseLogFile(target)
	}

	if err != nil {
		log.Fatal(err)
	}

	entries = filterEntries(entries)

	if *lastN > 0 && len(entries) > *lastN {
		entries = entries[len(entries)-*lastN:]
	}

	if *summary || *stats {
		showDetailedSummary(entries)
	} else if *report {
		generateReport(entries)
	} else if *groupBy != "" {
		showGrouped(entries)
	} else if *outputJSON {
		outputJSONEntries(entries)
	} else {
		showEntries(entries)
	}

	if *export != "" {
		exportEntries(entries, *export)
	}
}

func printUsage() {
	fmt.Printf("%s%sNginx Access Log Parser%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Println("A powerful CLI tool for analyzing Nginx access logs")
	fmt.Println()
	fmt.Printf("%sUsage:%s nginx-parse [options] <logfile|ssh-host>\n", ColorBold, ColorReset)
	fmt.Println()
	fmt.Printf("%sExamples:%s\n", ColorBold, ColorReset)
	fmt.Println("  nginx-parse /var/log/nginx/access.log")
	fmt.Println("  nginx-parse --status=5xx production")
	fmt.Println("  nginx-parse --slow-only --min-time=2.0 access.log")
	fmt.Println("  nginx-parse --errors-only --since=2025-06-13 web-server")
	fmt.Println("  nginx-parse --summary --exclude-bots --stats production")
	fmt.Println("  nginx-parse --group-by=status --top=20 access.log")
	fmt.Println()
	fmt.Printf("%sSSH Remote Logs:%s\n", ColorBold, ColorReset)
	fmt.Println("  If the target looks like an SSH host, it will:")
	fmt.Println("  1. Look up the host in your ~/.ssh/config")
	fmt.Println("  2. SSH to that host and fetch the log file")
	fmt.Println("  3. Parse it locally with all the same features")
	fmt.Println()
	fmt.Printf("%sFiltering Options:%s\n", ColorBold, ColorReset)
	fmt.Println("  --status=404           # Specific status")
	fmt.Println("  --status=4xx           # Status class")
	fmt.Println("  --method=POST          # HTTP method")
	fmt.Println("  --ip=192.168.1.0/24    # IP or CIDR")
	fmt.Println("  --slow-only            # Requests > 1s")
	fmt.Println("  --errors-only          # 4xx and 5xx only")
	fmt.Println("  --exclude-bots         # Filter out bot traffic")
	fmt.Println()
	fmt.Printf("%sOptions:%s\n", ColorBold, ColorReset)
	flag.PrintDefaults()
}

func isRemoteTarget(target string) bool {
	if strings.Contains(target, "/") || strings.HasSuffix(target, ".log") {
		return false
	}

	if _, err := os.Stat(target); err == nil {
		return false
	}

	return true
}

func parseRemoteLogFile(host string) ([]AccessLogEntry, error) {
	configPath := *sshConfig
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("could not find home directory: %v", err)
		}
		configPath = filepath.Join(home, ".ssh", "config")
	}

	sshHost, err := getSSHHostFromConfig(configPath, host)
	if err != nil {
		return nil, fmt.Errorf("SSH config error: %v", err)
	}

	cmd := exec.Command("ssh", sshHost, "cat", *remotePath)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start SSH command: %v", err)
	}

	entries, parseErr := parseLogReader(stdout)

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("SSH command failed: %v", err)
	}

	return entries, parseErr
}

func getSSHHostFromConfig(configPath, hostAlias string) (string, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return hostAlias, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inHostSection := false
	var hostname, user string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "Host ") {
			hosts := strings.Fields(line)[1:]
			inHostSection = false
			for _, h := range hosts {
				if h == hostAlias {
					inHostSection = true
					break
				}
			}
			continue
		}

		if !inHostSection {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := parts[1]

		switch key {
		case "hostname":
			hostname = value
		case "user":
			user = value
		}
	}

	if hostname == "" {
		hostname = hostAlias
	}

	sshTarget := hostname
	if user != "" {
		sshTarget = user + "@" + hostname
	}

	return sshTarget, nil
}

func parseLogFile(filename string) ([]AccessLogEntry, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseLogReader(file)
}

func parseLogReader(reader io.Reader) ([]AccessLogEntry, error) {
	var entries []AccessLogEntry
	scanner := bufio.NewScanner(reader)

	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	// Pattern for your specific format: IP - [timestamp] "request" status bytes "referer" "user_agent" "extra_field"
	customPattern := regexp.MustCompile(`^(\S+) - \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)" "([^"]*)"(?: ([0-9.]+))?(?: ([0-9.]+))?`)

	// Pattern for health checker format: - - [timestamp] "request" status bytes "referer" "user_agent" "extra_field"
	healthCheckerPattern := regexp.MustCompile(`^- - \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)" "([^"]*)"(?: ([0-9.]+))?(?: ([0-9.]+))?`)

	// Standard combined format with timing
	combinedPattern := regexp.MustCompile(`^(\S+) - - \[([^\]]+)\] "(\S+) ([^"]*) (HTTP/[\d.]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"(?: ([0-9.]+))?(?: ([0-9.]+))?`)

	// Simple combined format without timing
	simplePattern := regexp.MustCompile(`^(\S+) - - \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"`)

	lineCount := 0
	matchCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineCount++

		if (*debug || *showSamples) && lineCount <= 3 {
			fmt.Printf("Sample line %d: %s\n", lineCount, line)
		}

		var entry *AccessLogEntry

		// Try custom pattern first (your main format: IP - [timestamp] ...)
		if matches := customPattern.FindStringSubmatch(line); matches != nil {
			timestamp, _ := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2])

			status, _ := strconv.Atoi(matches[4])
			bytesSent, _ := strconv.ParseInt(matches[5], 10, 64)

			// Parse the request string "GET / HTTP/1.1"
			requestParts := strings.Fields(matches[3])
			method := ""
			uri := matches[3]
			protocol := ""

			if len(requestParts) >= 2 {
				method = requestParts[0]
				uri = requestParts[1]
				if len(requestParts) >= 3 {
					protocol = requestParts[2]
				}
			}

			var requestTime, upstreamTime float64
			if len(matches) > 9 && matches[9] != "" {
				requestTime, _ = strconv.ParseFloat(matches[9], 64)
			}
			if len(matches) > 10 && matches[10] != "" {
				upstreamTime, _ = strconv.ParseFloat(matches[10], 64)
			}

			entry = &AccessLogEntry{
				Timestamp:    timestamp,
				RemoteAddr:   matches[1],
				Method:       method,
				URI:          uri,
				Protocol:     protocol,
				Status:       status,
				BytesSent:    bytesSent,
				Referer:      matches[6],
				UserAgent:    matches[7],
				RequestTime:  requestTime,
				UpstreamTime: upstreamTime,
				Context:      make(map[string]interface{}),
			}

			// Store the user ID in both context and the UserID field for easy access
			if matches[8] != "-" && matches[8] != "" {
				entry.Context["user_id"] = matches[8]
				entry.RequestID = matches[8] // Reuse RequestID field for user ID display
			}

			matchCount++
		} else if matches := healthCheckerPattern.FindStringSubmatch(line); matches != nil {
			// Handle health checker logs (- - [timestamp] ...)
			timestamp, _ := time.Parse("02/Jan/2006:15:04:05 -0700", matches[1])

			status, _ := strconv.Atoi(matches[3])
			bytesSent, _ := strconv.ParseInt(matches[4], 10, 64)

			// Parse the request string "GET / HTTP/1.1"
			requestParts := strings.Fields(matches[2])
			method := ""
			uri := matches[2]
			protocol := ""

			if len(requestParts) >= 2 {
				method = requestParts[0]
				uri = requestParts[1]
				if len(requestParts) >= 3 {
					protocol = requestParts[2]
				}
			}

			var requestTime, upstreamTime float64
			if len(matches) > 8 && matches[8] != "" {
				requestTime, _ = strconv.ParseFloat(matches[8], 64)
			}
			if len(matches) > 9 && matches[9] != "" {
				upstreamTime, _ = strconv.ParseFloat(matches[9], 64)
			}

			entry = &AccessLogEntry{
				Timestamp:    timestamp,
				RemoteAddr:   "-", // Health checker has no IP
				Method:       method,
				URI:          uri,
				Protocol:     protocol,
				Status:       status,
				BytesSent:    bytesSent,
				Referer:      matches[5],
				UserAgent:    matches[6],
				RequestTime:  requestTime,
				UpstreamTime: upstreamTime,
				Context:      make(map[string]interface{}),
			}

			// Store the user ID in both context and RequestID field for display
			if len(matches) > 7 && matches[7] != "-" && matches[7] != "" {
				entry.Context["user_id"] = matches[7]
				entry.RequestID = matches[7]
			}

			matchCount++
		} else if matches := combinedPattern.FindStringSubmatch(line); matches != nil {
			timestamp, _ := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2])

			status, _ := strconv.Atoi(matches[6])
			bytesSent, _ := strconv.ParseInt(matches[7], 10, 64)

			var requestTime, upstreamTime float64
			if len(matches) > 10 && matches[10] != "" {
				requestTime, _ = strconv.ParseFloat(matches[10], 64)
			}
			if len(matches) > 11 && matches[11] != "" {
				upstreamTime, _ = strconv.ParseFloat(matches[11], 64)
			}

			entry = &AccessLogEntry{
				Timestamp:    timestamp,
				RemoteAddr:   matches[1],
				Method:       matches[3],
				URI:          matches[4],
				Protocol:     matches[5],
				Status:       status,
				BytesSent:    bytesSent,
				Referer:      matches[8],
				UserAgent:    matches[9],
				RequestTime:  requestTime,
				UpstreamTime: upstreamTime,
				Context:      make(map[string]interface{}),
			}
			matchCount++
		} else if matches := simplePattern.FindStringSubmatch(line); matches != nil {
			timestamp, _ := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2])

			status, _ := strconv.Atoi(matches[4])
			bytesSent, _ := strconv.ParseInt(matches[5], 10, 64)

			requestParts := strings.Fields(matches[3])
			method := ""
			uri := matches[3]
			protocol := ""

			if len(requestParts) >= 2 {
				method = requestParts[0]
				uri = requestParts[1]
				if len(requestParts) >= 3 {
					protocol = requestParts[2]
				}
			}

			entry = &AccessLogEntry{
				Timestamp:  timestamp,
				RemoteAddr: matches[1],
				Method:     method,
				URI:        uri,
				Protocol:   protocol,
				Status:     status,
				BytesSent:  bytesSent,
				Referer:    matches[6],
				UserAgent:  matches[7],
				Context:    make(map[string]interface{}),
			}
			matchCount++
		} else if (*debug || *showSamples) && lineCount <= 10 {
			fmt.Printf("Failed to parse line %d: %s\n", lineCount, line)
		}

		if entry != nil {
			entries = append(entries, *entry)
		}
	}

	if *debug || matchCount == 0 {
		fmt.Printf("Parsed %d lines, matched %d entries\n", lineCount, matchCount)
	}

	if matchCount == 0 && lineCount > 0 {
		fmt.Printf("No lines matched the expected nginx log format. Please check your log format.\n")
		fmt.Printf("Expected format: Combined Log Format with optional timing data\n")
		fmt.Printf("Try using --show-samples to see sample lines from your log\n")
	}

	return entries, scanner.Err()
}

func filterEntries(entries []AccessLogEntry) []AccessLogEntry {
	var filtered []AccessLogEntry

	var sinceTime, untilTime time.Time
	var err error

	if *since != "" {
		if strings.Contains(*since, " ") {
			sinceTime, err = time.Parse("2006-01-02 15:04", *since)
		} else {
			sinceTime, err = time.Parse("2006-01-02", *since)
		}
		if err != nil {
			log.Printf("Warning: invalid since date format: %v", err)
		}
	}

	if *until != "" {
		if strings.Contains(*until, " ") {
			untilTime, err = time.Parse("2006-01-02 15:04", *until)
		} else {
			untilTime, err = time.Parse("2006-01-02", *until)
			if err == nil {
				untilTime = untilTime.Add(24 * time.Hour)
			}
		}
		if err != nil {
			log.Printf("Warning: invalid until date format: %v", err)
		}
	}

	for _, entry := range entries {
		if *statusFilter != "" {
			if strings.HasSuffix(*statusFilter, "xx") {
				prefix := (*statusFilter)[:1]
				if !strings.HasPrefix(strconv.Itoa(entry.Status), prefix) {
					continue
				}
			} else if strconv.Itoa(entry.Status) != *statusFilter {
				continue
			}
		}

		if *errorsOnly && entry.Status < 400 {
			continue
		}

		if *methodFilter != "" && entry.Method != strings.ToUpper(*methodFilter) {
			continue
		}

		if *ipFilter != "" && !matchesIP(entry.RemoteAddr, *ipFilter) {
			continue
		}

		if *slowOnly && entry.RequestTime <= 1.0 {
			continue
		}

		if *minTime > 0 && entry.RequestTime < *minTime {
			continue
		}

		if *maxTime > 0 && entry.RequestTime > *maxTime {
			continue
		}

		if *minBytes > 0 && entry.BytesSent < *minBytes {
			continue
		}

		if *excludeBots && isBot(entry.UserAgent) {
			continue
		}

		if *pathFilter != "" && !matchesPath(entry.URI, *pathFilter) {
			continue
		}

		if *userFilter != "" && entry.RequestID != *userFilter {
			continue
		}

		if !sinceTime.IsZero() && entry.Timestamp.Before(sinceTime) {
			continue
		}

		if !untilTime.IsZero() && entry.Timestamp.After(untilTime) {
			continue
		}

		if *search != "" && !strings.Contains(strings.ToLower(entry.URI), strings.ToLower(*search)) {
			continue
		}

		filtered = append(filtered, entry)
	}

	return filtered
}

func matchesIP(remoteAddr, filter string) bool {
	if strings.Contains(filter, "/") {
		return true
	}
	return strings.Contains(remoteAddr, filter)
}

func matchesPath(uri, pattern string) bool {
	if u, err := url.Parse(uri); err == nil {
		uri = u.Path
	}

	if strings.Contains(pattern, "*") {
		pattern = strings.ReplaceAll(pattern, "*", ".*")
		matched, _ := regexp.MatchString(pattern, uri)
		return matched
	}

	return strings.Contains(uri, pattern)
}

func isBot(userAgent string) bool {
	botPatterns := []string{
		"bot", "crawler", "spider", "scraper", "curl", "wget",
		"python", "go-http", "facebookexternalhit", "twitterbot",
		"googlebot", "bingbot", "slurp", "duckduckbot",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range botPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}
	return false
}

func getStatusColor(status int) string {
	if *noColor {
		return ""
	}
	switch {
	case status >= 500:
		return ColorRed + ColorBold
	case status >= 400:
		return ColorYellow + ColorBold
	case status >= 300:
		return ColorBlue
	case status >= 200:
		return ColorGreen
	default:
		return ColorGray
	}
}

func getTimeColor() string {
	if *noColor {
		return ""
	}
	return ColorDim
}

func showEntries(entries []AccessLogEntry) {
	if len(entries) == 0 {
		fmt.Printf("%s%sNo access log entries found matching your criteria.%s\n", ColorYellow, ColorBold, ColorReset)
		return
	}

	for _, entry := range entries {
		if *compact {
			showCompactEntry(entry)
		} else {
			showDetailedEntry(entry)
		}
	}

	if !*noColor {
		fmt.Printf("\n%s%s%d entries found%s\n", ColorDim, ColorBold, len(entries), ColorReset)
	} else {
		fmt.Printf("\n%d entries found\n", len(entries))
	}
}

func showCompactEntry(entry AccessLogEntry) {
	timeColor := getTimeColor()
	statusColor := getStatusColor(entry.Status)

	fmt.Printf("%s%s%s %s%3d%s %s%-4s%s %s",
		timeColor, entry.Timestamp.Format("15:04:05"), ColorReset,
		statusColor, entry.Status, ColorReset,
		ColorBlue, entry.Method, ColorReset,
		entry.URI)

	if entry.RequestTime > 0 {
		timeColor := ColorGray
		if entry.RequestTime > 1.0 {
			timeColor = ColorYellow
		}
		if entry.RequestTime > 5.0 {
			timeColor = ColorRed
		}
		fmt.Printf(" %s(%.3fs)%s", timeColor, entry.RequestTime, ColorReset)
	}

	fmt.Printf(" %s%s%s", ColorPurple, entry.RemoteAddr, ColorReset)

	// Show user ID if available
	if entry.RequestID != "" {
		fmt.Printf(" %s[user:%s]%s", ColorCyan, entry.RequestID, ColorReset)
	}

	fmt.Println()
}

func showDetailedEntry(entry AccessLogEntry) {
	statusColor := getStatusColor(entry.Status)

	fmt.Printf("%s╭─ %s %s%d%s %s%s%s %s\n",
		ColorDim,
		entry.Timestamp.Format("2006-01-02 15:04:05"),
		statusColor, entry.Status, ColorReset,
		ColorBlue, entry.Method, ColorReset,
		entry.URI)

	fmt.Printf("%s│  %sIP: %s%s  %sBytes: %s%s%s",
		ColorDim, ColorGray, ColorPurple, entry.RemoteAddr, ColorReset,
		ColorGray, formatBytes(entry.BytesSent), ColorReset)

	if entry.RequestTime > 0 {
		color := ColorGreen
		if entry.RequestTime > 1.0 {
			color = ColorYellow
		}
		if entry.RequestTime > 5.0 {
			color = ColorRed
		}
		fmt.Printf("  %sTime: %s%.3fs%s", ColorGray, color, entry.RequestTime, ColorReset)
	}

	// Show user ID if available
	if entry.RequestID != "" {
		fmt.Printf("  %sUser: %s%s%s", ColorGray, ColorCyan, entry.RequestID, ColorReset)
	}

	fmt.Println()

	if entry.Referer != "-" && entry.Referer != "" {
		fmt.Printf("%s│  %sReferer: %s%s\n", ColorDim, ColorGray, ColorReset, truncateString(entry.Referer, 80))
	}

	if entry.UserAgent != "-" && entry.UserAgent != "" {
		uaColor := ColorReset
		if isBot(entry.UserAgent) {
			uaColor = ColorYellow
		}
		fmt.Printf("%s│  %sUA: %s%s%s\n", ColorDim, ColorGray, uaColor, truncateString(entry.UserAgent, 80), ColorReset)
	}

	fmt.Printf("%s╰─%s\n", ColorDim, ColorReset)
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func showDetailedSummary(entries []AccessLogEntry) {
	if len(entries) == 0 {
		fmt.Printf("%s%sNo access log entries found.%s\n", ColorYellow, ColorBold, ColorReset)
		return
	}

	statusCounts := make(map[int]int)
	methodCounts := make(map[string]int)
	topIPs := make(map[string]int)
	topURIs := make(map[string]int)
	topReferers := make(map[string]int)
	hourlyStats := make(map[string]int)

	var totalBytes int64
	var totalTime float64
	var slowRequests int
	var errorRequests int

	for _, entry := range entries {
		statusCounts[entry.Status]++
		methodCounts[entry.Method]++
		topIPs[entry.RemoteAddr]++

		uri := entry.URI
		if u, err := url.Parse(uri); err == nil {
			uri = u.Path
		}
		topURIs[uri]++

		if entry.Referer != "-" && entry.Referer != "" {
			topReferers[entry.Referer]++
		}

		hourlyStats[entry.Timestamp.Format("15:00")]++
		totalBytes += entry.BytesSent
		totalTime += entry.RequestTime

		if entry.RequestTime > 1.0 {
			slowRequests++
		}

		if entry.Status >= 400 {
			errorRequests++
		}
	}

	fmt.Printf("%s%sNginx Access Log Analysis%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s═══════════════════════════%s\n", ColorCyan, ColorReset)
	fmt.Printf("Total requests: %s%s%s\n", ColorBold, formatNumber(len(entries)), ColorReset)
	fmt.Printf("Time range: %s to %s\n",
		entries[0].Timestamp.Format("2006-01-02 15:04"),
		entries[len(entries)-1].Timestamp.Format("2006-01-02 15:04"))
	fmt.Printf("Total bytes served: %s%s%s\n", ColorBold, formatBytes(totalBytes), ColorReset)

	if totalTime > 0 {
		fmt.Printf("Avg response time: %s%.3fs%s\n", ColorBold, totalTime/float64(len(entries)), ColorReset)
	}

	fmt.Printf("Slow requests (>1s): %s%s (%.1f%%)%s\n",
		ColorYellow, formatNumber(slowRequests), float64(slowRequests)/float64(len(entries))*100, ColorReset)
	fmt.Printf("Error requests (4xx/5xx): %s%s (%.1f%%)%s\n",
		ColorRed, formatNumber(errorRequests), float64(errorRequests)/float64(len(entries))*100, ColorReset)

	fmt.Printf("\n%sHTTP Status Codes:%s\n", ColorBold, ColorReset)
	showStatusTopMap("Status", statusCounts, func(k int) string {
		return getStatusColor(k)
	})

	fmt.Printf("\n%sHTTP Methods:%s\n", ColorBold, ColorReset)
	showTopMap("Method", methodCounts, func(k string) string { return ColorBlue })

	if *stats {
		fmt.Printf("\n%sTop Client IPs:%s\n", ColorBold, ColorReset)
		showTopMap("IP", topIPs, func(k string) string { return ColorPurple })

		fmt.Printf("\n%sTop Requested URIs:%s\n", ColorBold, ColorReset)
		showTopMap("URI", topURIs, func(k string) string { return ColorCyan })

		if len(topReferers) > 0 {
			fmt.Printf("\n%sTop Referers:%s\n", ColorBold, ColorReset)
			showTopMap("Referer", topReferers, func(k string) string { return ColorGray })
		}
	}
}

func formatNumber(n int) string {
	str := strconv.Itoa(n)
	if len(str) <= 3 {
		return str
	}

	var result strings.Builder
	for i, char := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result.WriteString(",")
		}
		result.WriteRune(char)
	}
	return result.String()
}

func showStatusTopMap(label string, data map[int]int, colorFunc func(int) string) {
	type entry struct {
		key   int
		count int
	}

	var entries []entry
	for k, v := range data {
		entries = append(entries, entry{k, v})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count > entries[j].count
	})

	total := 0
	for _, count := range data {
		total += count
	}

	for i, e := range entries {
		if i >= *topN {
			break
		}
		color := colorFunc(e.key)
		percentage := float64(e.count) / float64(total) * 100
		fmt.Printf("  %s%-20d%s %s%s%s (%s%.1f%%%s)\n",
			color, e.key, ColorReset,
			ColorBold, formatNumber(e.count), ColorReset,
			ColorDim, percentage, ColorReset)
	}
}

func showTopMap(label string, data map[string]int, colorFunc func(string) string) {
	type entry struct {
		key   string
		count int
	}

	var entries []entry
	for k, v := range data {
		entries = append(entries, entry{k, v})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count > entries[j].count
	})

	for i, e := range entries {
		if i >= *topN {
			break
		}
		color := colorFunc(e.key)
		percentage := float64(e.count) / float64(getTotalCount(data)) * 100
		fmt.Printf("  %s%-20s%s %s%s%s (%s%.1f%%%s)\n",
			color, truncateString(e.key, 20), ColorReset,
			ColorBold, formatNumber(e.count), ColorReset,
			ColorDim, percentage, ColorReset)
	}
}

func getTotalCount(data map[string]int) int {
	total := 0
	for _, count := range data {
		total += count
	}
	return total
}

func showGrouped(entries []AccessLogEntry) {
	groups := make(map[string][]AccessLogEntry)

	for _, entry := range entries {
		var key string
		switch *groupBy {
		case "status":
			key = strconv.Itoa(entry.Status)
		case "method":
			key = entry.Method
		case "uri":
			if u, err := url.Parse(entry.URI); err == nil {
				key = truncateString(u.Path, 50)
			} else {
				key = truncateString(entry.URI, 50)
			}
		case "ip":
			key = entry.RemoteAddr
		case "user":
			key = entry.RequestID
			if key == "" {
				key = "anonymous"
			}
		case "hour":
			key = entry.Timestamp.Format("15:00")
		default:
			key = "unknown"
		}
		groups[key] = append(groups[key], entry)
	}

	type groupInfo struct {
		key     string
		entries []AccessLogEntry
	}

	var sortedGroups []groupInfo
	for key, entries := range groups {
		sortedGroups = append(sortedGroups, groupInfo{key, entries})
	}

	sort.Slice(sortedGroups, func(i, j int) bool {
		return len(sortedGroups[i].entries) > len(sortedGroups[j].entries)
	})

	for _, group := range sortedGroups {
		color := ColorCyan
		if *groupBy == "status" {
			if status, err := strconv.Atoi(group.key); err == nil {
				color = getStatusColor(status)
			}
		}

		fmt.Printf("\n%s%s━━━ %s (%s entries) ━━━%s\n",
			ColorBold, color, group.key, formatNumber(len(group.entries)), ColorReset)

		for i, entry := range group.entries {
			if i >= 5 {
				fmt.Printf("  %s... and %s more%s\n", ColorDim, formatNumber(len(group.entries)-5), ColorReset)
				break
			}
			fmt.Printf("  %s[%s]%s %s%d%s %s %s %s%s%s\n",
				getTimeColor(), entry.Timestamp.Format("15:04:05"), ColorReset,
				getStatusColor(entry.Status), entry.Status, ColorReset,
				entry.Method, truncateString(entry.URI, 60),
				ColorPurple, entry.RemoteAddr, ColorReset)
		}
	}
}

func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
}

func outputJSONEntries(entries []AccessLogEntry) {
	output, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(output))
}

func generateReport(entries []AccessLogEntry) {
	if len(entries) == 0 {
		return
	}

	fmt.Printf("%s%sNGINX ACCESS LOG REPORT%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s════════════════════════════════════════%s\n", ColorBold, ColorCyan, ColorReset)

	start := entries[0].Timestamp
	end := entries[len(entries)-1].Timestamp
	duration := end.Sub(start)

	fmt.Printf("Analysis Period: %s to %s (%.1f hours)\n",
		start.Format("2006-01-02 15:04"),
		end.Format("2006-01-02 15:04"),
		duration.Hours())

	statusCounts := make(map[int]int)
	var totalBytes int64
	var totalTime float64
	var validTimings int
	var slowRequests int
	var errorRequests int
	ips := make(map[string]bool)
	botRequests := 0

	for _, entry := range entries {
		statusCounts[entry.Status]++
		totalBytes += entry.BytesSent
		ips[entry.RemoteAddr] = true

		if entry.RequestTime > 0 {
			totalTime += entry.RequestTime
			validTimings++
			if entry.RequestTime > 1.0 {
				slowRequests++
			}
		}

		if entry.Status >= 400 {
			errorRequests++
		}

		if isBot(entry.UserAgent) {
			botRequests++
		}
	}

	rps := float64(len(entries)) / duration.Seconds()

	fmt.Printf("Total Requests: %s%s%s\n", ColorBold, formatNumber(len(entries)), ColorReset)
	fmt.Printf("Unique IPs: %s%s%s\n", ColorBold, formatNumber(len(ips)), ColorReset)
	fmt.Printf("Requests/Second: %s%.2f%s\n", ColorBold, rps, ColorReset)
	fmt.Printf("Total Bandwidth: %s%s%s\n", ColorBold, formatBytes(totalBytes), ColorReset)

	if validTimings > 0 {
		avgTime := totalTime / float64(validTimings)
		fmt.Printf("⏱Avg Response Time: %s%.3fs%s\n", ColorBold, avgTime, ColorReset)
	}

	errorRate := float64(errorRequests) / float64(len(entries)) * 100
	slowRate := float64(slowRequests) / float64(len(entries)) * 100
	botRate := float64(botRequests) / float64(len(entries)) * 100

	fmt.Printf("Error Rate: %s%.1f%%%s (%s requests)\n",
		getErrorRateColor(errorRate), errorRate, ColorReset, formatNumber(errorRequests))
	fmt.Printf("🐌 Slow Requests (>1s): %s%.1f%%%s (%s requests)\n",
		getSlowRateColor(slowRate), slowRate, ColorReset, formatNumber(slowRequests))
	fmt.Printf("Bot Traffic: %s%.1f%%%s (%s requests)\n",
		ColorYellow, botRate, ColorReset, formatNumber(botRequests))

	fmt.Printf("\n%sSTATUS CODE BREAKDOWN%s\n", ColorBold, ColorReset)
	showStatusBreakdown(statusCounts, len(entries))

	if *stats {
		fmt.Printf("\n%sDETAILED INSIGHTS%s\n", ColorBold, ColorReset)
		showTopEndpoints(entries)
		showTopErrorPages(entries)
		showTrafficPattern(entries)
	}
}

func getErrorRateColor(rate float64) string {
	if *noColor {
		return ""
	}
	switch {
	case rate > 10:
		return ColorRed + ColorBold
	case rate > 5:
		return ColorYellow + ColorBold
	default:
		return ColorGreen
	}
}

func getSlowRateColor(rate float64) string {
	if *noColor {
		return ""
	}
	switch {
	case rate > 20:
		return ColorRed + ColorBold
	case rate > 10:
		return ColorYellow + ColorBold
	default:
		return ColorGreen
	}
}

func showStatusBreakdown(statusCounts map[int]int, total int) {
	groups := map[string][]int{
		"Success (2xx)":      {200, 201, 202, 204, 206},
		"Redirect (3xx)":     {301, 302, 304, 307, 308},
		"Client Error (4xx)": {400, 401, 403, 404, 405, 429},
		"Server Error (5xx)": {500, 502, 503, 504, 505},
	}

	for label, codes := range groups {
		count := 0
		for _, code := range codes {
			count += statusCounts[code]
		}
		if count > 0 {
			percentage := float64(count) / float64(total) * 100
			fmt.Printf("  %s %s%s%s (%.1f%%)\n", label, ColorBold, formatNumber(count), ColorReset, percentage)
		}
	}
}

func showTopEndpoints(entries []AccessLogEntry) {
	endpointStats := make(map[string]struct {
		count      int
		totalTime  float64
		validTimes int
		totalBytes int64
		errors     int
	})

	for _, entry := range entries {
		path := entry.URI
		if u, err := url.Parse(entry.URI); err == nil {
			path = u.Path
		}

		stats := endpointStats[path]
		stats.count++
		stats.totalBytes += entry.BytesSent

		if entry.RequestTime > 0 {
			stats.totalTime += entry.RequestTime
			stats.validTimes++
		}

		if entry.Status >= 400 {
			stats.errors++
		}

		endpointStats[path] = stats
	}

	type endpoint struct {
		path  string
		stats struct {
			count      int
			totalTime  float64
			validTimes int
			totalBytes int64
			errors     int
		}
	}

	var endpoints []endpoint
	for path, stats := range endpointStats {
		endpoints = append(endpoints, endpoint{path, stats})
	}

	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].stats.count > endpoints[j].stats.count
	})

	fmt.Printf("Top Endpoints by Request Count:\n")
	for i, ep := range endpoints {
		if i >= 5 {
			break
		}

		avgTime := ""
		if ep.stats.validTimes > 0 {
			avg := ep.stats.totalTime / float64(ep.stats.validTimes)
			avgTime = fmt.Sprintf(" (%.3fs avg)", avg)
		}

		errorRate := ""
		if ep.stats.errors > 0 {
			rate := float64(ep.stats.errors) / float64(ep.stats.count) * 100
			errorRate = fmt.Sprintf(" %s%.1f%% errors%s", ColorRed, rate, ColorReset)
		}

		fmt.Printf("  %s%d.%s %s%s%s - %s requests%s%s\n",
			ColorCyan, i+1, ColorReset,
			ColorBold, truncateString(ep.path, 40), ColorReset,
			formatNumber(ep.stats.count), avgTime, errorRate)
	}
}

func showTopErrorPages(entries []AccessLogEntry) {
	errorPages := make(map[string]int)

	for _, entry := range entries {
		if entry.Status >= 400 {
			path := entry.URI
			if u, err := url.Parse(entry.URI); err == nil {
				path = u.Path
			}
			errorPages[path]++
		}
	}

	if len(errorPages) == 0 {
		return
	}

	type errorPage struct {
		path  string
		count int
	}

	var pages []errorPage
	for path, count := range errorPages {
		pages = append(pages, errorPage{path, count})
	}

	sort.Slice(pages, func(i, j int) bool {
		return pages[i].count > pages[j].count
	})

	fmt.Printf("\nMost Common Error Pages:\n")
	for i, page := range pages {
		if i >= 5 {
			break
		}
		fmt.Printf("  %s%d.%s %s%s%s - %s%s%s errors\n",
			ColorRed, i+1, ColorReset,
			ColorBold, truncateString(page.path, 40), ColorReset,
			ColorRed, formatNumber(page.count), ColorReset)
	}
}

func showTrafficPattern(entries []AccessLogEntry) {
	hourlyTraffic := make(map[int]int)

	for _, entry := range entries {
		hour := entry.Timestamp.Hour()
		hourlyTraffic[hour]++
	}

	fmt.Printf("\nTraffic Pattern (24-hour):\n")

	maxTraffic := 0
	for _, count := range hourlyTraffic {
		if count > maxTraffic {
			maxTraffic = count
		}
	}

	for hour := 0; hour < 24; hour++ {
		count := hourlyTraffic[hour]
		if count == 0 {
			continue
		}

		barLength := int(float64(count) / float64(maxTraffic) * 40)
		bar := strings.Repeat("█", barLength)

		fmt.Printf("  %02d:00 %s%s%s %s\n",
			hour, ColorBlue, bar, ColorReset, formatNumber(count))
	}
}

func exportEntries(entries []AccessLogEntry, format string) {
	switch strings.ToLower(format) {
	case "csv":
		exportCSV(entries)
	case "json":
		exportJSON(entries)
	default:
		log.Printf("Unknown export format: %s. Supported: csv, json", format)
	}
}

func exportCSV(entries []AccessLogEntry) {
	filename := fmt.Sprintf("nginx_access_%s.csv", time.Now().Format("20060102_150405"))
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Failed to create CSV file: %v", err)
		return
	}
	defer file.Close()

	fmt.Fprintf(file, "timestamp,remote_addr,method,uri,status,bytes_sent,referer,user_agent,user_id,request_time\n")

	for _, entry := range entries {
		fmt.Fprintf(file, "%s,%s,%s,\"%s\",%d,%d,\"%s\",\"%s\",%s,%.3f\n",
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			entry.RemoteAddr,
			entry.Method,
			strings.ReplaceAll(entry.URI, "\"", "\"\""),
			entry.Status,
			entry.BytesSent,
			strings.ReplaceAll(entry.Referer, "\"", "\"\""),
			strings.ReplaceAll(entry.UserAgent, "\"", "\"\""),
			entry.RequestID,
			entry.RequestTime)
	}

	fmt.Printf("Exported %d entries to %s\n", len(entries), filename)
}

func exportJSON(entries []AccessLogEntry) {
	filename := fmt.Sprintf("nginx_access_%s.json", time.Now().Format("20060102_150405"))
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Failed to create JSON file: %v", err)
		return
	}
	defer file.Close()

	output, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal JSON: %v", err)
		return
	}

	file.Write(output)
	fmt.Printf("✅ Exported %d entries to %s\n", len(entries), filename)
}

func followLogFile(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	file.Seek(0, 2)

	fmt.Printf("%s%sFollowing %s... (Ctrl+C to stop)%s\n", ColorDim, ColorCyan, filename, ColorReset)

	scanner := bufio.NewScanner(file)
	for {
		for scanner.Scan() {
			line := scanner.Text()
			if entry := parseSingleLine(line); entry != nil {
				if matchesFilters(*entry) {
					if *compact {
						showCompactEntry(*entry)
					} else {
						showDetailedEntry(*entry)
					}
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func parseSingleLine(line string) *AccessLogEntry {
	combinedPattern := regexp.MustCompile(`^(\S+) - - \[([^\]]+)\] "(\S+) ([^"]*) (HTTP/[\d.]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"(?: ([0-9.]+))?(?: ([0-9.]+))?`)

	if matches := combinedPattern.FindStringSubmatch(line); matches != nil {
		timestamp, _ := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2])

		status, _ := strconv.Atoi(matches[6])
		bytesSent, _ := strconv.ParseInt(matches[7], 10, 64)

		var requestTime, upstreamTime float64
		if len(matches) > 10 && matches[10] != "" {
			requestTime, _ = strconv.ParseFloat(matches[10], 64)
		}
		if len(matches) > 11 && matches[11] != "" {
			upstreamTime, _ = strconv.ParseFloat(matches[11], 64)
		}

		return &AccessLogEntry{
			Timestamp:    timestamp,
			RemoteAddr:   matches[1],
			Method:       matches[3],
			URI:          matches[4],
			Protocol:     matches[5],
			Status:       status,
			BytesSent:    bytesSent,
			Referer:      matches[8],
			UserAgent:    matches[9],
			RequestTime:  requestTime,
			UpstreamTime: upstreamTime,
			Context:      make(map[string]interface{}),
		}
	}
	return nil
}

func matchesFilters(entry AccessLogEntry) bool {
	if *statusFilter != "" {
		if strings.HasSuffix(*statusFilter, "xx") {
			prefix := (*statusFilter)[:1]
			if !strings.HasPrefix(strconv.Itoa(entry.Status), prefix) {
				return false
			}
		} else if strconv.Itoa(entry.Status) != *statusFilter {
			return false
		}
	}

	if *errorsOnly && entry.Status < 400 {
		return false
	}

	if *methodFilter != "" && entry.Method != strings.ToUpper(*methodFilter) {
		return false
	}

	if *slowOnly && entry.RequestTime <= 1.0 {
		return false
	}

	if *excludeBots && isBot(entry.UserAgent) {
		return false
	}

	if *search != "" && !strings.Contains(strings.ToLower(entry.URI), strings.ToLower(*search)) {
		return false
	}

	return true
}
