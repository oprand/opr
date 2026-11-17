package registry

import (
	"testing"

	"github.com/oprand/opr/internal/opconst"

	"go.uber.org/zap"
)

func TestNewAcceptsLowercaseRegistry(t *testing.T) {
	t.Parallel()
	aggr, err := New(zap.NewNop(), nil, Options{OnlyRegistries: []string{"arin"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(aggr.RegistriesOfInterest) != 1 || aggr.RegistriesOfInterest[0] != opconst.ARIN {
		t.Fatalf("registries = %v, want [ARIN]", aggr.RegistriesOfInterest)
	}
}
