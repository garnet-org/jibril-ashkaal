package ongoing

import (
	"encoding/json"
	"sync"

	"github.com/garnet-org/jibril-ashkaal/pkg/kind"
)

// OnGoingSimple is a simple implementation of the OnGoing interface.

type OnGoingSimple struct {
	uuid    string
	kind    kind.Kind
	private map[string]any
	data    map[string]any
	mutex   sync.Mutex
}

func NewOnGoingSimple(uuid string, k kind.Kind) *OnGoingSimple {
	return &OnGoingSimple{
		uuid:    uuid,
		kind:    k,
		private: make(map[string]any),
		data:    make(map[string]any),
	}
}

func (g *OnGoingSimple) Destroy() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.uuid = ""
	g.kind = kind.KindNone
	for k := range g.private {
		delete(g.private, k)
	}
	g.private = nil
	for k := range g.data {
		delete(g.data, k)
	}
	g.data = nil
}

func (g *OnGoingSimple) UUID() string {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	return g.uuid
}

func (g *OnGoingSimple) Kind() kind.Kind {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	return g.kind
}

func (g *OnGoingSimple) SetPrivate(key string, value any) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.private[key] = value
}

func (g *OnGoingSimple) GetPrivate(key string) any {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if v, ok := g.private[key]; ok {
		return v
	}
	return nil
}

func (g *OnGoingSimple) DelPrivate(key string) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	delete(g.private, key)
}

func (g *OnGoingSimple) Duplicate() OnGoing {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	dataCopy := make(map[string]any, len(g.data))
	privateCopy := make(map[string]any, len(g.private))

	for k, v := range g.data {
		dataCopy[k] = v
	}
	for k, v := range g.private {
		privateCopy[k] = v
	}

	return &OnGoingSimple{
		uuid:    g.uuid,
		kind:    g.kind,
		data:    dataCopy,
		private: privateCopy,
	}
}

func (g *OnGoingSimple) Add(given map[string]any) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	for k, value := range given {
		if _, exists := g.data[k]; !exists {
			g.data[k] = value
		}
	}
}

func (g *OnGoingSimple) Del(key string) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	delete(g.data, key)
}

func (g *OnGoingSimple) Serialize() []byte {
	g.mutex.Lock()
	snapshot := g.deepCopyDataUnlocked()
	g.mutex.Unlock()
	serialized, _ := json.Marshal(snapshot)
	return serialized
}

// Private methods.

func (g *OnGoingSimple) deepCopyDataUnlocked() map[string]any {
	copied := make(map[string]any, len(g.data))
	for k, v := range g.data {
		copied[k] = v
	}
	return copied
}
