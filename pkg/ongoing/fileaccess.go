package ongoing

import (
	"encoding/json"
	"sync"

	"github.com/garnet-org/jibril-ashkaal/pkg/kind"
)

type OnGoingFileAccess struct {
	FileAccess *FileAccess
	private    map[string]any
	mutex      sync.RWMutex
}

func NewOnGoingFileAccess(given *FileAccess) *OnGoingFileAccess {
	return &OnGoingFileAccess{
		FileAccess: given,
		private:    make(map[string]any),
	}
}

func (g *OnGoingFileAccess) Clone() OnGoing {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return &OnGoingFileAccess{
		FileAccess: g.FileAccess.Clone(),
		private:    g.private,
	}
}

func (g *OnGoingFileAccess) Kind() kind.Kind {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return kind.KindDetections
}

func (g *OnGoingFileAccess) Base() *Base {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.FileAccess.Base
}

func (g *OnGoingFileAccess) Item() any {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.FileAccess
}

func (g *OnGoingFileAccess) SetPrivate(key string, value any) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.private[key] = value
}

func (g *OnGoingFileAccess) GetPrivate(key string) any {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	if v, ok := g.private[key]; ok {
		return v
	}
	return nil
}

func (g *OnGoingFileAccess) Serialize() []byte {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	serialized, _ := json.Marshal(g.FileAccess)
	return serialized
}

func (g *OnGoingFileAccess) Destroy() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.FileAccess = &FileAccess{}
	g.private = nil
}
