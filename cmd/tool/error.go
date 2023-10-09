package main

import "fmt"

const packageName string = "codacy-trivy/tool"

// ToolError is the error returned when failing to run the tool.
type ToolError struct {
	// msg is the error message explaining what operation failed.
	msg string
	// w is the underlying error.
	w error
}

func (e ToolError) Error() string {
	if e.w == nil {
		return fmt.Sprintf("%s: %s", packageName, e.msg)
	}
	return fmt.Sprintf("%s: %s\n%s", packageName, e.msg, e.w.Error())
}
func (e ToolError) Unwrap() error {
	return e.w
}
