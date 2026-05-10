package apperror

import (
	stderrors "errors"
)

type Error struct {
	status  int
	code    string
	message string
	cause   error
}

func New(status int, code, message string, cause error) *Error {
	return &Error{
		status:  status,
		code:    code,
		message: message,
		cause:   cause,
	}
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}

	if e.cause == nil {
		return e.message
	}

	return e.message + ": " + e.cause.Error()
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.cause
}

func (e *Error) Status() int {
	if e == nil {
		return 0
	}

	return e.status
}

func (e *Error) Code() string {
	if e == nil {
		return ""
	}

	return e.code
}

func (e *Error) Message() string {
	if e == nil {
		return ""
	}

	return e.message
}

func As(err error) (*Error, bool) {
	var appErr *Error
	if !stderrors.As(err, &appErr) {
		return nil, false
	}

	return appErr, true
}
