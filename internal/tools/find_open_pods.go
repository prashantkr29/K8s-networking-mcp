package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

var K8sClient *kubernetes.Clientset

func init() {
	registerTool(MCPTool[Find_open_podsToolParams, Find_open_podsToolResult]{
		Name:        "find_open_pods",
		Description: "Find pods with no NetworkPolicy selecting them",
		Handler: func(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[Find_open_podsToolParams]) (*mcp.CallToolResultFor[Find_open_podsToolResult], error) {
			result, err := runFind_open_podsTool(params.Arguments)
			if err != nil {
				return nil, err
			}
			return &mcp.CallToolResultFor[Find_open_podsToolResult]{
				Content: []mcp.Content{
					&mcp.TextContent{
						Text: result.Namespace,
					},
				},
			}, nil
		},
	})
}

type Find_open_podsToolParams struct {
	Namespace string `json:"namespace" description:"Kubernetes namespace to get the workloads from"`
}

type OpenPod struct {
	Name    string            `json:"name"`
	Labels  map[string]string `json:"labels"`
	Ingress string            `json:"ingress"`
	Egress  string            `json:"egress"`
}

type Find_open_podsToolResult struct {
	OpenPods  []OpenPod `json:"open_pods"`
	Count     int       `json:"pods_counted"`
	Namespace string    `json:"namespace"`
}

func runFind_open_podsTool(args Find_open_podsToolParams) (Find_open_podsToolResult, error) {
	ns := args.Namespace
	if ns == "" {
		ns = "default"
	}

	empty := Find_open_podsToolResult{
		OpenPods:  []OpenPod{},
		Count:     0,
		Namespace: ns,
	}

	// fetch pods
	pods, err := K8sClient.CoreV1().Pods(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return empty, fmt.Errorf("failed to fetch pods: %w", err)
	}

	// fetch network policies
	policies, err := K8sClient.NetworkingV1().NetworkPolicies(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return empty, fmt.Errorf("failed to fetch network policies: %w", err)
	}

	// pre-compute selectors from all policies
	type parsedPolicy struct {
		selector      labels.Selector
		coversIngress bool
		coversEgress  bool
	}

	var parsed []parsedPolicy
	for _, policy := range policies.Items {
		sel, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if err != nil {
			continue // skip malformed selectors
		}
		coversIngress := false
		coversEgress := false
		for _, pt := range policy.Spec.PolicyTypes {
			if pt == "Ingress" {
				coversIngress = true
			}
			if pt == "Egress" {
				coversEgress = true
			}
		}
		// if PolicyTypes is empty, k8s defaults to Ingress only
		if len(policy.Spec.PolicyTypes) == 0 {
			coversIngress = true
		}
		parsed = append(parsed, parsedPolicy{
			selector:      sel,
			coversIngress: coversIngress,
			coversEgress:  coversEgress,
		})
	}

	// check each pod against all policies
	var openPods []OpenPod
	for _, pod := range pods.Items {
		podLabels := labels.Set(pod.Labels)
		ingressProtected := false
		egressProtected := false

		for _, p := range parsed {
			if p.selector.Matches(podLabels) {
				if p.coversIngress {
					ingressProtected = true
				}
				if p.coversEgress {
					egressProtected = true
				}
			}
		}
		//pod having zero policies being invisible to the network policies -> Open pods
		if !ingressProtected && !egressProtected {
			ingress := "protected"
			if !ingressProtected {
				ingress = "open"
			}
			egress := "protected"
			if !egressProtected {
				egress = "open"
			}
			openPods = append(openPods, OpenPod{
				Name:    pod.Name,
				Labels:  pod.Labels,
				Ingress: ingress,
				Egress:  egress,
			})
		}
	}

	//explicit return at end of function
	return Find_open_podsToolResult{
		OpenPods:  openPods,
		Count:     len(openPods),
		Namespace: ns,
	}, nil
}
