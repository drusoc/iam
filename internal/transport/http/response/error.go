package response

type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

func NewError(message, code string) ErrorResponse {
	return ErrorResponse{
		Error: ErrorBody{
			Message: message,
			Code:    code,
		},
	}
}
