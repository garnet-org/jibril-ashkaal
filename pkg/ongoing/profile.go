package ongoing

import (
	"encoding/json"
	"sync"

	"github.com/garnet-org/jibril-ashkaal/pkg/kind"
)

type OnGoingProfile struct {
	Profile Profile
	private map[string]any
	mutex   sync.RWMutex
}

func NewOnGoingProfile(given Profile) *OnGoingProfile {
	return &OnGoingProfile{
		Profile: given,
		private: make(map[string]any),
	}
}

func (g *OnGoingProfile) Clone() OnGoing {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	private := make(map[string]any)
	for k, v := range g.private {
		private[k] = v
	}

	return &OnGoingProfile{
		Profile: g.Profile.Clone(),
		private: private,
	}
}

func (g *OnGoingProfile) Kind() kind.Kind {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return kind.KindProfile
}

func (g *OnGoingProfile) Base() Base {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.Profile.Base
}

func (g *OnGoingProfile) Item() any {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.Profile
}

func (g *OnGoingProfile) SetPrivate(key string, value any) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.private[key] = value
}

func (g *OnGoingProfile) GetPrivate(key string) any {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	if v, ok := g.private[key]; ok {
		return v
	}
	return nil
}

func (g *OnGoingProfile) Serialize() []byte {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	serialized, _ := json.Marshal(g.Profile)
	return serialized
}

func (g *OnGoingProfile) Destroy() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.Profile = Profile{}
	g.private = nil
}

func (g *OnGoingProfile) SetScore(score Score) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.Profile.Base.Score = score
}

func (g *OnGoingProfile) GetScore() Score {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.Profile.Base.Score
}

func (g *OnGoingProfile) SetAttenuator(attenuator Attenuator) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.Profile.Base.Attenuator = attenuator
}

func (g *OnGoingProfile) GetAttenuator() Attenuator {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.Profile.Base.Attenuator
}
