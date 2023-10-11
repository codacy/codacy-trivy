package docgen

import "fmt"

const packageName string = "codacy-trivy/docgen"

// DocGenError is the error returned when failing to generate the tool's documentation.
type DocGenError struct {
	// msg is the error message explaining what operation failed.
	msg string
	// w is the underlying error.
	w error
}

func (e DocGenError) Error() string {
	if e.w == nil {
		return fmt.Sprintf("%s: %s", packageName, e.msg)
	}
	return fmt.Sprintf("%s: %s\n%s", packageName, e.msg, e.w.Error())
}
func (e DocGenError) Unwrap() error {
	return e.w
}
