package tools

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
	registerTool(MCPTool[GetDNSErrorsParams, GetDNSErrorsResult]{
		Name:        "get_dns_errors",
		Description: "Find DNS resolution errors (NXDOMAIN, SERVFAIL) for pods in a namespace by parsing CoreDNS logs",
		Handler: func(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[GetDNSErrorsParams]) (*mcp.CallToolResultFor[GetDNSErrorsResult], error) {
			result, err := runGetDNSErrors(ctx, params.Arguments)
			if err != nil {
				return nil, err
			}
			return &mcp.CallToolResultFor[GetDNSErrorsResult]{
				Content: []mcp.Content{
					&mcp.TextContent{Text: result.Summary},
				},
			}, nil
		},
	})
}

//Input / Output

type GetDNSErrorsParams struct {
	Namespace string `json:"namespace"  description:"Namespace to filter DNS errors for"`
	TailLines int64  `json:"tail_lines" description:"Number of CoreDNS log lines to scan (default: 500)"`
}

type DNSError struct {
	PodName   string `json:"pod_name"`   // pod that made the failing query
	PodIP     string `json:"pod_ip"`     // source IP from CoreDNS log
	Query     string `json:"query"`      // the DNS name that failed
	ErrorType string `json:"error_type"` // NXDOMAIN | SERVFAIL | TIMEOUT
	Count     int    `json:"count"`      // how many times this error occurred
	LastSeen  string `json:"last_seen"`  // timestamp of most recent occurrence
}

type GetDNSErrorsResult struct {
	Namespace      string     `json:"namespace"`
	ErrorCount     int        `json:"error_count"`
	Errors         []DNSError `json:"errors"`
	TopFailedQuery string     `json:"top_failed_query"` // most frequent failing DNS name
	Summary        string     `json:"summary"`
}

//logic

func runGetDNSErrors(ctx context.Context, args GetDNSErrorsParams) (GetDNSErrorsResult, error) {
	ns := args.Namespace
	if ns == "" {
		ns = "default"
	}
	tailLines := args.TailLines
	if tailLines == 0 {
		tailLines = 500
	}

	empty := GetDNSErrorsResult{
		Namespace:  ns,
		ErrorCount: 0,
		Errors:     []DNSError{},
	}

	//build podIP -> podName map for the target namespace
	ipToPod, err := buildIPToPodMap(ctx, ns)
	if err != nil {
		return empty, fmt.Errorf("failed to list pods: %w", err)
	}

	//find CoreDNS pods (always in kube-system)
	coreDNSPods, err := K8sClient.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=kube-dns",
	})
	if err != nil {
		return empty, fmt.Errorf("failed to find CoreDNS pods: %w", err)
	}
	if len(coreDNSPods.Items) == 0 {
		return empty, fmt.Errorf("no CoreDNS pods found in kube-system")
	}

	//collect error lines from all CoreDNS pods
	// key: "podIP:query:errorType" -> DNSError
	errorMap := make(map[string]*DNSError)

	for _, corePod := range coreDNSPods.Items {
		logs, err := fetchPodLogs(ctx, "kube-system", corePod.Name, tailLines)
		if err != nil {
			// one CoreDNS pod failing to stream logs shouldn't abort everything
			continue
		}

		parseCoreDNSLogs(logs, ipToPod, errorMap)
	}

	//flatten map -> slice, find top failed query
	var errors []DNSError
	topQuery := ""
	topCount := 0

	for _, e := range errorMap {
		errors = append(errors, *e)
		if e.Count > topCount {
			topCount = e.Count
			topQuery = e.Query
		}
	}

	summary := buildDNSSummary(ns, errors, topQuery)

	return GetDNSErrorsResult{
		Namespace:      ns,
		ErrorCount:     len(errors),
		Errors:         errors,
		TopFailedQuery: topQuery,
		Summary:        summary,
	}, nil
}

//CoreDNS log parser
// parseCoreDNSLogs scans log lines and extracts DNS errors
// for pods whose IPs are in ipToPod (i.e. in our target namespace)

// CoreDNS log format:
// [INFO] <clientIP>:<port> - <id> "<type> IN <query> udp ..." <RCODE> ...
// [ERROR] plugin/errors: 2 SERVFAIL <query>.
func parseCoreDNSLogs(logs string, ipToPod map[string]string, errorMap map[string]*DNSError) {
	scanner := bufio.NewScanner(strings.NewReader(logs))

	for scanner.Scan() {
		line := scanner.Text()

		// check for error response codes in info lines
		// format: [INFO] 10.244.1.5:52134 - 12345 "A IN payments.svc.cluster.local. udp ..." NXDOMAIN ...
		if strings.Contains(line, "NXDOMAIN") || strings.Contains(line, "SERVFAIL") {
			entry := parseInfoLine(line, ipToPod)
			if entry != nil {
				key := fmt.Sprintf("%s:%s:%s", entry.PodIP, entry.Query, entry.ErrorType)
				if existing, ok := errorMap[key]; ok {
					existing.Count++
					existing.LastSeen = entry.LastSeen
				} else {
					entry.Count = 1
					errorMap[key] = entry
				}
			}
		}

		// [ERROR] plugin/errors lines
		if strings.HasPrefix(line, "[ERROR]") && strings.Contains(line, "SERVFAIL") {
			entry := parseErrorLine(line)
			if entry != nil {
				key := fmt.Sprintf("unknown:%s:SERVFAIL", entry.Query)
				if existing, ok := errorMap[key]; ok {
					existing.Count++
				} else {
					entry.Count = 1
					errorMap[key] = entry
				}
			}
		}
	}
}

// parseInfoLine handles the standard CoreDNS query log format
func parseInfoLine(line string, ipToPod map[string]string) *DNSError {
	// extract client IP — it's the first token after [INFO]
	// example: [INFO] 10.244.1.5:52134 - 12345 "A IN redis.default.svc.cluster.local. udp 45 false 512" NXDOMAIN ...
	parts := strings.Fields(line)
	if len(parts) < 6 {
		return nil
	}

	// parts[1] = "10.244.1.5:52134"
	clientAddr := parts[1]
	clientIP := clientAddr
	if idx := strings.LastIndex(clientAddr, ":"); idx != -1 {
		clientIP = clientAddr[:idx]
	}

	// extract query from the quoted section
	// find content between first " and second "
	queryStart := strings.Index(line, `"`)
	queryEnd := strings.LastIndex(line, `"`)
	if queryStart == -1 || queryStart == queryEnd {
		return nil
	}
	quoted := line[queryStart+1 : queryEnd]
	// quoted = "A IN redis.default.svc.cluster.local. udp 45 false 512"
	quotedParts := strings.Fields(quoted)
	if len(quotedParts) < 3 {
		return nil
	}
	query := quotedParts[2] // "redis.default.svc.cluster.local."
	query = strings.TrimSuffix(query, ".")

	// determine error type
	errorType := ""
	if strings.Contains(line, "NXDOMAIN") {
		errorType = "NXDOMAIN"
	} else if strings.Contains(line, "SERVFAIL") {
		errorType = "SERVFAIL"
	}
	if errorType == "" {
		return nil
	}

	// resolve IP to pod name
	podName, ok := ipToPod[clientIP]
	if !ok {
		// IP not in our target namespace — skip
		return nil
	}

	return &DNSError{
		PodName:   podName,
		PodIP:     clientIP,
		Query:     query,
		ErrorType: errorType,
		LastSeen:  time.Now().UTC().Format(time.RFC3339),
	}
}

// parseErrorLine handles [ERROR] plugin/errors lines
func parseErrorLine(line string) *DNSError {
	// [ERROR] plugin/errors: 2 SERVFAIL payments.svc.cluster.local.
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return nil
	}
	query := strings.TrimSuffix(parts[len(parts)-1], ".")
	return &DNSError{
		PodName:   "unknown",
		PodIP:     "unknown",
		Query:     query,
		ErrorType: "SERVFAIL",
		LastSeen:  time.Now().UTC().Format(time.RFC3339),
	}
}

//Helpers

// buildIPToPodMap creates podIP → podName for all pods in a namespace
func buildIPToPodMap(ctx context.Context, namespace string) (map[string]string, error) {
	pods, err := K8sClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(pods.Items))
	for _, pod := range pods.Items {
		if pod.Status.PodIP != "" {
			m[pod.Status.PodIP] = pod.Name
		}
	}
	return m, nil
}

// fetchPodLogs streams logs from a pod as a string
func fetchPodLogs(ctx context.Context, namespace, podName string, tailLines int64) (string, error) {
	req := K8sClient.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		TailLines: &tailLines,
	})
	stream, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to stream logs from %s: %w", podName, err)
	}
	defer stream.Close()

	var sb strings.Builder
	if _, err := io.Copy(&sb, stream); err != nil {
		return "", fmt.Errorf("failed to read logs from %s: %w", podName, err)
	}
	return sb.String(), nil
}

func buildDNSSummary(ns string, errors []DNSError, topQuery string) string {
	if len(errors) == 0 {
		return fmt.Sprintf("no DNS errors found for pods in namespace '%s'", ns)
	}

	nxdomainCount := 0
	servfailCount := 0
	for _, e := range errors {
		switch e.ErrorType {
		case "NXDOMAIN":
			nxdomainCount += e.Count
		case "SERVFAIL":
			servfailCount += e.Count
		}
	}

	parts := []string{
		fmt.Sprintf("found %d DNS error(s) for namespace '%s'", len(errors), ns),
	}
	if nxdomainCount > 0 {
		parts = append(parts, fmt.Sprintf("%d NXDOMAIN", nxdomainCount))
	}
	if servfailCount > 0 {
		parts = append(parts, fmt.Sprintf("%d SERVFAIL", servfailCount))
	}
	if topQuery != "" {
		parts = append(parts, fmt.Sprintf("top failing query: %s", topQuery))
	}

	return strings.Join(parts, " | ")
}
