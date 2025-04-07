package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetupRouter_NotNil(t *testing.T) {
	router := SetupRouter()
	assert.NotNil(t, router, "El router no debería ser nil")
}
