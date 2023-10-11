package main

import (
	codacy "github.com/codacy/codacy-engine-golang-seed/v5"
	"github.com/codacy/codacy-trivy/internal/tool"
)

func main() {
	codacyTrivy := &tool.CodacyTrivy{}
	codacy.StartTool(codacyTrivy)
}
