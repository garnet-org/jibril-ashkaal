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

	// Clone the private map.
	private := make(map[string]any)
	for k, v := range g.private {
		private[k] = v
	}

	return &OnGoingNetworkPeer{
		NetworkPeer: g.NetworkPeer.Clone(),
		private:     private,
	}
}

func (g *OnGoingNetworkPeer) Kind() kind.Kind {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return kind.KindDetections
}

func (g *OnGoingNetworkPeer) Base() Base {
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

func (g *OnGoingNetworkPeer) SetScore(score Score) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.NetworkPeer.Base.Score = score
}

func (g *OnGoingNetworkPeer) SetAttenuator(attenuator Attenuator) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.NetworkPeer.Base.Attenuator = attenuator
}

func (g *OnGoingNetworkPeer) SetScenario(scenario ScenarioType) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	switch scenario.Type() {
	case ScenarioTypeGitHub.String():
		g.NetworkPeer.Base.Scenarios.GitHub = scenario.(ScenarioGitHub)
		return
	case ScenarioTypeHostOS.String():
		g.NetworkPeer.Base.Scenarios.HostOS = scenario.(ScenarioHostOS)
		return
	case ScenarioTypeK8S.String():
		g.NetworkPeer.Base.Scenarios.K8S = scenario.(ScenarioK8S)
		return
	}
}
