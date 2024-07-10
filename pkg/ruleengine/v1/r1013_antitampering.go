package ruleengine

import (
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracerantitamperingtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/antitampering/types"
)

const (
	R1013ID   = "R1013"
	R1013Name = "Antitampering"
)

var R1013AntitamperingRuleDescriptor = RuleDescriptor{
	ID:          R1013ID,
	Name:        R1013Name,
	Description: "Detecting tampering with our agent.",
	Tags:        []string{"malicious"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.AntitamperingEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1013Antitampering()
	},
}
var _ ruleengine.RuleEvaluator = (*R1013Antitampering)(nil)

type R1013Antitampering struct {
	BaseRule
}

func CreateRuleR1013Antitampering() *R1013Antitampering {
	return &R1013Antitampering{}
}

func (rule *R1013Antitampering) Name() string {
	return R1013Name
}

func (rule *R1013Antitampering) ID() string {
	return R1013ID
}

func (rule *R1013Antitampering) DeleteRule() {
}

func (rule *R1013Antitampering) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.AntitamperingEventType {
		return nil
	}

	antiTamperingEvent, ok := event.(*tracerantitamperingtype.Event)
	if !ok {
		return nil
	}

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      rule.Name(),
			InfectedPID:    antiTamperingEvent.Pid,
			FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			Severity:       R1013AntitamperingRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm:       antiTamperingEvent.Comm,
				PPID:       antiTamperingEvent.PPid,
				PID:        antiTamperingEvent.Pid,
				UpperLayer: &antiTamperingEvent.UpperLayer,
				Uid:        &antiTamperingEvent.Uid,
				Gid:        &antiTamperingEvent.Gid,
				Path:       antiTamperingEvent.ExePath,
			},
			ContainerID: antiTamperingEvent.Runtime.ContainerID,
		},
		TriggerEvent: antiTamperingEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: "Tampering detected with the agent.",
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName: antiTamperingEvent.GetPod(),
		},
		RuleID: rule.ID(),
	}
}

func (rule *R1013Antitampering) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1013AntitamperingRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
