package containerwatcher

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	tracerdns "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/tracer"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) dnsEventCallback(event *tracerdnstype.Event) {
	if event.Type != types.NORMAL {
		logger.L().Ctx(ch.ctx).Warning("dns tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	ch.containerCollection.EnrichByMntNs(&event.CommonData, event.MountNsID)

	_ = ch.dnsWorkerPool.Invoke(*event)
}

func (ch *IGContainerWatcher) startDNSTracing() error {
	if err := ch.tracerCollection.AddTracer(dnsTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	tracerDns, err := tracerdns.NewTracer()
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}

	tracerDns.SetEventHandler(ch.dnsEventCallback)

	ch.dnsTracer = tracerDns

	config := &networktracer.ConnectToContainerCollectionConfig[tracerdnstype.Event]{
		Tracer:   ch.dnsTracer,
		Resolver: ch.containerCollection,
		Selector: ch.containerSelector,
		Base:     tracerdnstype.Base,
	}

	_, err = networktracer.ConnectToContainerCollection(config)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}

	return nil
}

func (ch *IGContainerWatcher) stopDNSTracing() error {
	// Stop dns tracer
	if err := ch.tracerCollection.RemoveTracer(dnsTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}

	ch.dnsTracer.Close()

	return nil
}
