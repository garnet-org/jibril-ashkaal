package ongoing

import (
	"encoding/json"
	"sync"

	"github.com/garnet-org/jibril-ashkaal/pkg/kind"
)

type OnGoingDropIP struct {
	DropIP  *DropIP
	private map[string]any
	mutex   sync.RWMutex
}

func NewOnGoingDropIP(given *DropIP) *OnGoingDropIP {
	return &OnGoingDropIP{
		DropIP:  given,
		private: make(map[string]any),
	}
}

func (g *OnGoingDropIP) Clone() OnGoing {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return &OnGoingDropIP{
		DropIP:  g.DropIP.Clone(),
		private: g.private,
	}
}

func (g *OnGoingDropIP) Kind() kind.Kind {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return kind.KindDetections
}

func (g *OnGoingDropIP) Base() *Base {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.DropIP.Base
}

func (g *OnGoingDropIP) Item() any {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.DropIP
}

func (g *OnGoingDropIP) SetPrivate(key string, value any) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.private[key] = value
}

func (g *OnGoingDropIP) GetPrivate(key string) any {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	if v, ok := g.private[key]; ok {
		return v
	}
	return nil
}

func (g *OnGoingDropIP) Serialize() []byte {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	serialized, _ := json.Marshal(g.DropIP)
	return serialized
}

func (g *OnGoingDropIP) Destroy() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.DropIP = &DropIP{}
	g.private = nil
}
