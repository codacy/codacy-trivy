package main

import (
	"os"

	codacy "github.com/codacy/codacy-engine-golang-seed/v8"
	"github.com/codacy/codacy-trivy/internal/tool"
	"github.com/sirupsen/logrus"
)

func main() {
	codacyTrivy, err := tool.New(tool.MaliciousPackagesIndexPath)
	if err != nil {
		logrus.Errorf("Failed to create tool execution: %s", err.Error())
		os.Exit(-1)
	}

	retCode := codacy.StartTool(codacyTrivy)

	os.Exit(retCode)
}
