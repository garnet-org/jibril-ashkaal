package ongoing

import (
	"encoding/json"
	"sync"

	"github.com/garnet-org/jibril-ashkaal/pkg/kind"
)

type OnGoingNetworkPeer struct {
	NetworkPeer NetworkPeer
	private     map[string]any
	mutex       sync.RWMutex
}

func NewOnGoingNetworkPeer(given NetworkPeer) *OnGoingNetworkPeer {
	return &OnGoingNetworkPeer{
		NetworkPeer: given,
		private:     make(map[string]any),
	}
}

func (g *OnGoingNetworkPeer) Clone() OnGoing {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return &OnGoingNetworkPeer{
		NetworkPeer: g.NetworkPeer.Clone(),
		private:     g.private,
	}
}

func (g *OnGoingNetworkPeer) Kind() kind.Kind {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return kind.KindDetections
}

func (g *OnGoingNetworkPeer) Base() *Base {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.NetworkPeer.Base
}

func (g *OnGoingNetworkPeer) Item() any {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.NetworkPeer
}

func (g *OnGoingNetworkPeer) SetPrivate(key string, value any) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.private[key] = value
}

func (g *OnGoingNetworkPeer) GetPrivate(key string) any {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	if v, ok := g.private[key]; ok {
		return v
	}
	return nil
}

func (g *OnGoingNetworkPeer) Serialize() []byte {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	serialized, _ := json.Marshal(g.NetworkPeer)
	return serialized
}

func (g *OnGoingNetworkPeer) Destroy() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.NetworkPeer = NetworkPeer{}
	g.private = nil
}
