package main

import (
	"os"

	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"github.com/codacy/codacy-trivy/internal/tool"
)

func main() {
	codacyTrivy := tool.New()
	retCode := codacy.StartTool(&codacyTrivy)

	os.Exit(retCode)
}
