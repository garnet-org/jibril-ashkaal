package ongoing

import "github.com/garnet-org/jibril-ashkaal/pkg/kind"

// OnGoingEmpty is an empty implementation of the OnGoing interface.
// It is used as a placeholder for errors.

type OnGoingEmpty struct{}

func NewOnGoingEmpty() *OnGoingEmpty { return &OnGoingEmpty{} }

func (*OnGoingEmpty) Clone() OnGoing { return &OnGoingEmpty{} }

func (*OnGoingEmpty) Kind() kind.Kind { return kind.KindEmpty }

func (*OnGoingEmpty) Base() Base { return Base{} }

func (*OnGoingEmpty) Item() any { return nil }

func (*OnGoingEmpty) SetPrivate(string, any) {}

func (*OnGoingEmpty) GetPrivate(string) any { return nil }

func (*OnGoingEmpty) Serialize() []byte { return []byte{} }

func (*OnGoingEmpty) Destroy() {}
