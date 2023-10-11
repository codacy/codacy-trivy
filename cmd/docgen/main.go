package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/codacy/codacy-trivy/internal/docgen"
)

// docFolder is the folder where generated documentation will be placed.
var docFolder string

func main() {
	flag.StringVar(&docFolder, "docFolder", "docs", "Tool documentation folder")
	flag.Parse()

	documentationGenerator := docgen.New()
	if err := documentationGenerator.Generate(docFolder); err != nil {
		fmt.Printf("codacy-trivy: Failed to generate documentation %s", err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}
