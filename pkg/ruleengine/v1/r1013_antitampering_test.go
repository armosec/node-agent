package ruleengine

import (
	"testing"

	tracerantitamperingtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/antitampering/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

func TestR1013Antitampering(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1013Antitampering() // Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create antitampering event
	e := &tracerantitamperingtype.Event{
		Comm:    "test",
		MapName: "test",
	}

	ruleResult := r.ProcessEvent(utils.AntitamperingEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since antitampering event occured")
		return
	}
}
