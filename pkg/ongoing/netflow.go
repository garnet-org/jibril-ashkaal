package ongoing

import (
	"encoding/json"
	"sync"

	"github.com/garnet-org/jibril-ashkaal/pkg/kind"
)

type OnGoingNetworkFlow struct {
	NetworkFlow *NetworkFlow
	private     map[string]any
	mutex       sync.RWMutex
}

func NewOnGoingNetworkFlow(given *NetworkFlow) *OnGoingNetworkFlow {
	return &OnGoingNetworkFlow{
		NetworkFlow: given,
		private:     make(map[string]any),
	}
}

func (g *OnGoingNetworkFlow) Clone() OnGoing {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return &OnGoingNetworkFlow{
		NetworkFlow: g.NetworkFlow,
		private:     g.private,
	}
}

func (g *OnGoingNetworkFlow) Kind() kind.Kind {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return kind.KindFlows
}

func (g *OnGoingNetworkFlow) Base() *Base {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.NetworkFlow.Base
}

func (g *OnGoingNetworkFlow) Item() any {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.NetworkFlow
}

func (g *OnGoingNetworkFlow) SetPrivate(key string, value any) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.private[key] = value
}

func (g *OnGoingNetworkFlow) GetPrivate(key string) any {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	if v, ok := g.private[key]; ok {
		return v
	}
	return nil
}

func (g *OnGoingNetworkFlow) Serialize() []byte {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	serialized, _ := json.Marshal(g.NetworkFlow)
	return serialized
}

func (g *OnGoingNetworkFlow) Destroy() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.NetworkFlow = &NetworkFlow{}
	g.private = nil
}
