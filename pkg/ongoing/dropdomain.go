package ongoing

import (
	"encoding/json"
	"sync"

	"github.com/garnet-org/jibril-ashkaal/pkg/kind"
)

type OnGoingDropDomain struct {
	DropDomain *DropDomain
	private    map[string]any
	mutex      sync.RWMutex
}

func NewOnGoingDropDomain(given *DropDomain) *OnGoingDropDomain {
	return &OnGoingDropDomain{
		DropDomain: given,
		private:    make(map[string]any),
	}
}

func (g *OnGoingDropDomain) Clone() OnGoing {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return &OnGoingDropDomain{
		DropDomain: g.DropDomain.Clone(),
		private:    g.private,
	}
}

func (g *OnGoingDropDomain) Kind() kind.Kind {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return kind.KindDetections
}

func (g *OnGoingDropDomain) Base() *Base {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.DropDomain.Base
}

func (g *OnGoingDropDomain) Item() any {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.DropDomain
}

func (g *OnGoingDropDomain) SetPrivate(key string, value any) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.private[key] = value
}

func (g *OnGoingDropDomain) GetPrivate(key string) any {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	if v, ok := g.private[key]; ok {
		return v
	}
	return nil
}

func (g *OnGoingDropDomain) Serialize() []byte {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	serialized, _ := json.Marshal(g.DropDomain)
	return serialized
}

func (g *OnGoingDropDomain) Destroy() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.DropDomain = &DropDomain{}
	g.private = nil
}
