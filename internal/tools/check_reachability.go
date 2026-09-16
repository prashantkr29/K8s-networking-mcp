package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func init() {
	registerTool(MCPTool[CheckReachabilityParams, CheckReachabilityResult]{
		Name:        "check_reachability",
		Description: "Check if a source pod can reach a destination pod on a given port",
		Handler: func(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[CheckReachabilityParams]) (*mcp.CallToolResultFor[CheckReachabilityResult], error) {
			result, err := runCheckReachability(ctx, params.Arguments)
			if err != nil {
				return nil, err
			}
			return &mcp.CallToolResultFor[CheckReachabilityResult]{
				Content: []mcp.Content{
					&mcp.TextContent{Text: result.Reason},
				},
			}, nil
		},
	})
}

//Input / Output

type CheckReachabilityParams struct {
	SourcePod       string `json:"source_pod"       description:"Name of the source pod"`
	SourceNamespace string `json:"source_namespace" description:"Namespace of the source pod"`
	DestPod         string `json:"dest_pod"         description:"Name of the destination pod"`
	DestNamespace   string `json:"dest_namespace"   description:"Namespace of the destination pod"`
	Port            int32  `json:"port"             description:"Port number to check"`
	Protocol        string `json:"protocol"         description:"Protocol: TCP or UDP (default: TCP)"`
}

type CheckReachabilityResult struct {
	Allowed        bool     `json:"allowed"`
	Reason         string   `json:"reason"`
	EgressVerdict  string   `json:"egress_verdict"`  // "allowed" | "denied" | "no_policy"
	IngressVerdict string   `json:"ingress_verdict"` // "allowed" | "denied" | "no_policy"
	AllowedBy      []string `json:"allowed_by"`      // policy names that allow traffic
	BlockedBy      []string `json:"blocked_by"`      // policy names that block traffic
}

//logic

func runCheckReachability(ctx context.Context, args CheckReachabilityParams) (CheckReachabilityResult, error) {
	// default protocol
	protocol := args.Protocol
	if protocol == "" {
		protocol = "TCP"
	}

	srcNs := args.SourceNamespace
	dstNs := args.DestNamespace
	if srcNs == "" {
		srcNs = "default"
	}
	if dstNs == "" {
		dstNs = "default"
	}

	denied := func(reason, verdict string, blockedBy []string) (CheckReachabilityResult, error) {
		return CheckReachabilityResult{
			Allowed:        false,
			Reason:         reason,
			BlockedBy:      blockedBy,
			EgressVerdict:  ifString(verdict == "egress", "denied", "allowed"),
			IngressVerdict: ifString(verdict == "ingress", "denied", "allowed"),
		}, nil
	}

	//fetch source pod
	srcPod, err := K8sClient.CoreV1().Pods(srcNs).Get(ctx, args.SourcePod, metav1.GetOptions{})
	if err != nil {
		return CheckReachabilityResult{}, fmt.Errorf("source pod not found: %w", err)
	}

	//fetch dest pod
	dstPod, err := K8sClient.CoreV1().Pods(dstNs).Get(ctx, args.DestPod, metav1.GetOptions{})
	if err != nil {
		return CheckReachabilityResult{}, fmt.Errorf("dest pod not found: %w", err)
	}

	//fetch source namespace (for namespaceSelector matching)
	srcNamespace, err := K8sClient.CoreV1().Namespaces().Get(ctx, srcNs, metav1.GetOptions{})
	if err != nil {
		return CheckReachabilityResult{}, fmt.Errorf("source namespace not found: %w", err)
	}

	//fetch all policies in BOTH namespaces
	srcPolicies, err := K8sClient.NetworkingV1().NetworkPolicies(srcNs).List(ctx, metav1.ListOptions{})
	if err != nil {
		return CheckReachabilityResult{}, fmt.Errorf("failed to list source policies: %w", err)
	}

	dstPolicies, err := K8sClient.NetworkingV1().NetworkPolicies(dstNs).List(ctx, metav1.ListOptions{})
	if err != nil {
		return CheckReachabilityResult{}, fmt.Errorf("failed to list dest policies: %w", err)
	}

	srcPodLabels := labels.Set(srcPod.Labels)
	dstPodLabels := labels.Set(dstPod.Labels)
	srcNsLabels := labels.Set(srcNamespace.Labels)

	// check EGRESS on source pod
	// find all egress policies that select the source pod
	var egressPolicies []networkingv1.NetworkPolicy
	for _, p := range srcPolicies.Items {
		if !coversEgress(p) {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(&p.Spec.PodSelector)
		if err != nil {
			continue
		}
		if sel.Matches(srcPodLabels) {
			egressPolicies = append(egressPolicies, p)
		}
	}

	egressVerdict := "no_policy"
	var allowedBy []string
	var blockedBy []string

	if len(egressPolicies) > 0 {
		// source pod is egress-isolated — must find an explicit allow rule
		egressAllowed := false
		for _, policy := range egressPolicies {
			if matchesEgressRule(policy, dstPodLabels, dstNs, args.Port, protocol) {
				egressAllowed = true
				allowedBy = append(allowedBy, policy.Name)
			} else {
				blockedBy = append(blockedBy, policy.Name)
			}
		}
		if !egressAllowed {
			return denied(
				fmt.Sprintf("egress blocked on source pod '%s': no egress rule allows traffic to '%s' on port %d",
					args.SourcePod, args.DestPod, args.Port),
				"egress",
				blockedBy,
			)
		}
		egressVerdict = "allowed"
	}

	// check INGRESS on dest pod
	var ingressPolicies []networkingv1.NetworkPolicy
	for _, p := range dstPolicies.Items {
		if !coversIngress(p) {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(&p.Spec.PodSelector)
		if err != nil {
			continue
		}
		if sel.Matches(dstPodLabels) {
			ingressPolicies = append(ingressPolicies, p)
		}
	}

	ingressVerdict := "no_policy"

	if len(ingressPolicies) > 0 {
		//dest pod is ingress-isolated — must find an explicit allow rule
		ingressAllowed := false
		for _, policy := range ingressPolicies {
			if matchesIngressRule(policy, srcPodLabels, srcNsLabels, srcNs, dstNs, args.Port, protocol) {
				ingressAllowed = true
				allowedBy = append(allowedBy, policy.Name)
			} else {
				blockedBy = append(blockedBy, policy.Name)
			}
		}
		if !ingressAllowed {
			return denied(
				fmt.Sprintf("ingress blocked on dest pod '%s': no ingress rule allows traffic from '%s' on port %d",
					args.DestPod, args.SourcePod, args.Port),
				"ingress",
				blockedBy,
			)
		}
		ingressVerdict = "allowed"
	}

	return CheckReachabilityResult{
		Allowed:        true,
		Reason:         fmt.Sprintf("traffic allowed from '%s' to '%s' on port %d/%s", args.SourcePod, args.DestPod, args.Port, protocol),
		EgressVerdict:  egressVerdict,
		IngressVerdict: ingressVerdict,
		AllowedBy:      allowedBy,
		BlockedBy:      []string{},
	}, nil
}

func coversIngress(p networkingv1.NetworkPolicy) bool {
	if len(p.Spec.PolicyTypes) == 0 {
		return true // k8s default: empty PolicyTypes means Ingress
	}
	for _, pt := range p.Spec.PolicyTypes {
		if pt == networkingv1.PolicyTypeIngress {
			return true
		}
	}
	return false
}

func coversEgress(p networkingv1.NetworkPolicy) bool {
	for _, pt := range p.Spec.PolicyTypes {
		if pt == networkingv1.PolicyTypeEgress {
			return true
		}
	}
	return false
}

// matchesEgressRule checks if any egress rule in the policy allows
// traffic to the destination pod on the given port
func matchesEgressRule(
	policy networkingv1.NetworkPolicy,
	dstLabels labels.Set,
	dstNamespace string,
	port int32,
	protocol string,
) bool {
	for _, rule := range policy.Spec.Egress {
		// check port match first
		if !portMatches(rule.Ports, port, protocol) {
			continue
		}
		// empty To means allow all destinations
		if len(rule.To) == 0 {
			return true
		}
		for _, peer := range rule.To {
			if peerMatchesDest(peer, dstLabels, dstNamespace, policy.Namespace) {
				return true
			}
		}
	}
	return false
}

// matchesIngressRule checks if any ingress rule in the policy allows
// traffic from the source pod on the given port
func matchesIngressRule(
	policy networkingv1.NetworkPolicy,
	srcLabels labels.Set,
	srcNsLabels labels.Set,
	srcNamespace string,
	dstNamespace string,
	port int32,
	protocol string,
) bool {
	for _, rule := range policy.Spec.Ingress {
		if !portMatches(rule.Ports, port, protocol) {
			continue
		}
		// empty From means allow all sources
		if len(rule.From) == 0 {
			return true
		}
		for _, peer := range rule.From {
			if peerMatchesSource(peer, srcLabels, srcNsLabels, srcNamespace, dstNamespace) {
				return true
			}
		}
	}
	return false
}

// peerMatchesSource handles the AND vs OR logic for ingress peers
// This is the subtle part — podSelector and namespaceSelector
// in the SAME peer entry are AND, in separate entries are OR
func peerMatchesSource(
	peer networkingv1.NetworkPolicyPeer,
	srcLabels labels.Set,
	srcNsLabels labels.Set,
	srcNamespace string,
	dstNamespace string,
) bool {
	podMatch := true
	nsMatch := true

	if peer.PodSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil {
			return false
		}
		podMatch = sel.Matches(srcLabels)
	}

	if peer.NamespaceSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
		if err != nil {
			return false
		}
		nsMatch = sel.Matches(srcNsLabels)
	} else {
		// no namespaceSelector -> only same namespace is allowed
		nsMatch = srcNamespace == dstNamespace
	}

	return podMatch && nsMatch // AND within the same peer entry
}

// peerMatchesDest is the egress equivalent of peerMatchesSource
func peerMatchesDest(
	peer networkingv1.NetworkPolicyPeer,
	dstLabels labels.Set,
	dstNamespace string,
	policyNamespace string,
) bool {
	podMatch := true
	nsMatch := true

	if peer.PodSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil {
			return false
		}
		podMatch = sel.Matches(dstLabels)
	}

	if peer.NamespaceSelector != nil {
		// we'd need dest namespace labels here -> fetch them separately
		// for now scope to same namespace if no namespaceSelector
		_ = dstNamespace
		nsMatch = true
	} else {
		nsMatch = dstNamespace == policyNamespace
	}

	return podMatch && nsMatch
}

// portMatches checks if the target port/protocol is covered by the rule's ports
// empty ports list means ALL ports are allowed
func portMatches(ports []networkingv1.NetworkPolicyPort, port int32, protocol string) bool {
	if len(ports) == 0 {
		return true // no port restriction -> all ports allowed
	}
	for _, p := range ports {
		// protocol check
		if p.Protocol != nil && string(*p.Protocol) != protocol {
			continue
		}
		// port check
		if p.Port == nil {
			return true // nil port means all ports
		}
		if p.Port.IntVal == port {
			return true
		}
	}
	return false
}

func ifString(condition bool, a, b string) string {
	if condition {
		return a
	}
	return b
}
