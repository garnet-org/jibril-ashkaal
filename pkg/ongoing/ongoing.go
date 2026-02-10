package ongoing

import "github.com/garnet-org/jibril-ashkaal/pkg/kind"

// OnGoing is the interface for all ongoing data.

type OnGoing interface {
	Kind() kind.Kind
	Base() Base
	Item() any
	SetPrivate(string, any)
	GetPrivate(string) any
	Serialize() []byte
	Clone() OnGoing
	Destroy()
	SetScore(score Score)
	SetAttenuator(attenuator Attenuator)
	GetScore() Score
	GetAttenuator() Attenuator
}
