package main

import (
	codacy "github.com/codacy/codacy-engine-golang-seed/v5"
)

func main() {
	codacy.StartTool(&CodacyTrivy{})
}
