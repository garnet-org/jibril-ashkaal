package ongoing

import (
	"encoding/json"
	"sync"

	"github.com/garnet-org/jibril-ashkaal/pkg/kind"
)

type OnGoingExecution struct {
	Execution *Execution
	private   map[string]any
	mutex     sync.RWMutex
}

func NewOnGoingExecution(given *Execution) *OnGoingExecution {
	return &OnGoingExecution{
		Execution: given,
		private:   make(map[string]any),
	}
}

func (g *OnGoingExecution) Clone() OnGoing {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return &OnGoingExecution{
		Execution: g.Execution.Clone(),
		private:   g.private,
	}
}

func (g *OnGoingExecution) Kind() kind.Kind {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return kind.KindDetections
}

func (g *OnGoingExecution) Base() *Base {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.Execution.Base
}

func (g *OnGoingExecution) Item() any {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.Execution
}

func (g *OnGoingExecution) SetPrivate(key string, value any) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.private[key] = value
}

func (g *OnGoingExecution) GetPrivate(key string) any {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	if v, ok := g.private[key]; ok {
		return v
	}
	return nil
}

func (g *OnGoingExecution) Serialize() []byte {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	serialized, _ := json.Marshal(g.Execution)
	return serialized
}

func (g *OnGoingExecution) Destroy() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.Execution = &Execution{}
	g.private = nil
}
