// File: internal/errs/errs.go

package errs

import (
	"errors"
	"fmt"
)

// Common error types
var (
	ErrNotFound         = errors.New("not found")
	ErrAlreadyExists    = errors.New("already exists")
	ErrInvalidInput     = errors.New("invalid input")
	ErrUnauthorized     = errors.New("unauthorized")
	ErrForbidden        = errors.New("forbidden")
	ErrInternal         = errors.New("internal error")
	ErrConflict         = errors.New("conflict")
	ErrNotImplemented   = errors.New("not implemented")
	ErrUnavailable      = errors.New("service unavailable")
	ErrTimeout          = errors.New("timeout")
	ErrInvalidOperation = errors.New("invalid operation")
	ErrValidationFailed = errors.New("validation failed")
	ErrInvalidArgument  = errors.New("invalid argument")
	ErrValidation       = errors.New("validation error")
	ErrInvalidSession   = errors.New("invalid session")
)

// Layer represents the application layer where the error occurred
type Layer string

const (
	LayerRepository Layer = "repository"
	LayerService    Layer = "service"
	LayerFacade     Layer = "facade"
	LayerHandler    Layer = "handler"
	LayerValidator  Layer = "validator"
)

// ValidationError represents a validation error with field and message
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Error represents a structured application error
type Error struct {
	// The original error that occurred
	Err error

	// The layer where the error originated
	Layer Layer

	// Additional context about the error
	Message string

	// The operation that was being performed when the error occurred
	Operation string

	// Optional additional metadata
	Metadata map[string]interface{}
}

// Error implements the error interface
func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("[%s] %s: %s: %v", e.Layer, e.Operation, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s: %v", e.Layer, e.Operation, e.Err)
}

// Unwrap implements the errors.Unwrap interface
func (e *Error) Unwrap() error {
	return e.Err
}

// New creates a new Error with the given layer and operation
func New(layer Layer, operation string, err error, message string) *Error {
	return &Error{
		Err:       err,
		Layer:     layer,
		Operation: operation,
		Message:   message,
	}
}

// Wrap wraps an existing error with layer and operation context
func Wrap(layer Layer, operation string, err error, message string) *Error {
	if err == nil {
		return nil
	}

	var e *Error
	if errors.As(err, &e) {
		// Already wrapped, preserve the original layer
		return e
	}

	return New(layer, operation, err, message)
}

// WithMetadata adds metadata to the error
func (e *Error) withMetadata(key string, value interface{}) *Error {
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	e.Metadata[key] = value
	return e
}

// Helper functions for each layer

// RepositoryError wraps a repository layer error
func RepositoryError(operation string, err error, message string) *Error {
	return Wrap(LayerRepository, operation, err, message)
}

// ServiceError wraps a service layer error
func ServiceError(operation string, err error, message string) *Error {
	return Wrap(LayerService, operation, err, message)
}

// FacadeError wraps a facade layer error
func FacadeError(operation string, err error, message string) *Error {
	return Wrap(LayerFacade, operation, err, message)
}

// HandlerError wraps a handler layer error
func HandlerError(operation string, err error, message string) *Error {
	return Wrap(LayerHandler, operation, err, message)
}

// Is checks if the target error is of type Error and matches the layer and operation
func Is(err error, layer Layer, operation string) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Layer == layer && e.Operation == operation
	}
	return false
}

// Matches checks if the error matches the target error (similar to errors.Is)
func Matches(err, target error) bool {
	return errors.Is(err, target)
}

// GetLayer returns the layer of the error if it's an Error type
func GetLayer(err error) (Layer, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Layer, true
	}
	return "", false
}

// GetOperation returns the operation of the error if it's an Error type
func GetOperation(err error) (string, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Operation, true
	}
	return "", false
}

// ValidatorError wraps a validator layer error
func ValidatorError(operation string, err error, message string) *Error {
	return Wrap(LayerValidator, operation, err, message)
}

// ValidationErrors creates a new validation error with metadata containing the validation errors
func ValidationErrors(operation string, validationErrors []ValidationError) *Error {
	err := New(LayerValidator, operation, ErrValidationFailed, "validation failed")
	for _, ve := range validationErrors {
		_ = err.withMetadata(ve.Field, ve.Message)
	}
	return err
}

// IsValidationError checks if the error is a validation error
func IsValidationError(err error) bool {
	if e, ok := asError(err); ok {
		return e.Layer == LayerValidator && errors.Is(e.Err, ErrValidationFailed)
	}
	return false
}

// GetValidationErrors returns the validation errors if the error is a validation error
func GetValidationErrors(err error) (map[string]interface{}, bool) {
	var e *Error
	if errors.As(err, &e) {
		if e.Layer == LayerValidator && errors.Is(e.Err, ErrValidationFailed) {
			return e.Metadata, true
		}
	}
	return nil, false
}

func asError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
