package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"iam/internal/apperror"
	"iam/internal/config"
	accountdomain "iam/internal/domain/account"
	oauthdto "iam/internal/usecase/oauth/dto"
	oauthmocks "iam/internal/usecase/oauth/mocks"
	sessiondto "iam/internal/usecase/session/dto"
	sessionmocks "iam/internal/usecase/session/mocks"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestHandlerStartGoogleAuth(t *testing.T) {
	ctrl := gomock.NewController(t)

	e := echo.New()
	oauthUC := oauthmocks.NewMockUsecase(ctrl)
	sessionUC := sessionmocks.NewMockUsecase(ctrl)

	oauthUC.EXPECT().
		StartGoogleAuth(gomock.Any(), oauthdto.StartGoogleAuthIn{}).
		Return(&oauthdto.StartGoogleAuthOut{
			RedirectURL: "https://accounts.google.com/o/oauth2/auth?state=state-123",
		}, nil)

	handler := NewHandler(
		oauthUC,
		sessionUC,
		config.AuthConfig{},
	)

	request := httptest.NewRequest(http.MethodGet, "/api/1/auth/google/start", nil)
	recorder := httptest.NewRecorder()

	err := handler.StartGoogleAuth(e.NewContext(request, recorder))

	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, recorder.Code)
	assert.Equal(t, "https://accounts.google.com/o/oauth2/auth?state=state-123", recorder.Header().Get(echo.HeaderLocation))
}

func TestHandlerHandleGoogleCallback(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(oauthUC *oauthmocks.MockUsecase)
		location    string
		expectedURL string
	}{
		{
			name: "success_redirect",
			setupMock: func(oauthUC *oauthmocks.MockUsecase) {
				oauthUC.EXPECT().
					HandleGoogleCallback(gomock.Any(), oauthdto.HandleGoogleCallbackIn{
						Code:  "code-123",
						State: "state-123",
					}).
					Return(&oauthdto.HandleGoogleCallbackOut{
						RedirectURL: "http://localhost:3000/auth/success?code=one-time",
					}, nil)
			},
			location: "http://localhost:3000/auth/success?code=one-time",
		},
		{
			name: "error_redirect",
			setupMock: func(oauthUC *oauthmocks.MockUsecase) {
				oauthUC.EXPECT().
					HandleGoogleCallback(gomock.Any(), oauthdto.HandleGoogleCallbackIn{
						Code:  "code-123",
						State: "state-123",
					}).
					Return(nil, apperror.InvalidState(nil))
			},
			location: "http://localhost:3000/auth/error?error=invalid-state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			e := echo.New()
			oauthUC := oauthmocks.NewMockUsecase(ctrl)
			sessionUC := sessionmocks.NewMockUsecase(ctrl)

			tt.setupMock(oauthUC)

			handler := NewHandler(
				oauthUC,
				sessionUC,
				config.AuthConfig{
					ErrorURL: "http://localhost:3000/auth/error",
				},
			)

			request := httptest.NewRequest(
				http.MethodGet,
				"/api/1/auth/google/callback?code=code-123&state=state-123",
				nil,
			)
			recorder := httptest.NewRecorder()

			err := handler.HandleGoogleCallback(e.NewContext(request, recorder))

			require.NoError(t, err)
			assert.Equal(t, http.StatusFound, recorder.Code)
			assert.Equal(t, tt.location, recorder.Header().Get(echo.HeaderLocation))
		})
	}
}

func TestHandlerExchangeAuthCode(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(oauthUC *oauthmocks.MockUsecase)
		status    int
		check     func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name: "success_sets_dual_cookie",
			setupMock: func(oauthUC *oauthmocks.MockUsecase) {
				oauthUC.EXPECT().
					ExchangeAuthCode(gomock.Any(), oauthdto.ExchangeAuthCodeIn{
						Code: "one-time-code",
					}).
					Return(&oauthdto.ExchangeAuthCodeOut{
						SessionID:    "session-123",
						RefreshToken: "refresh-456",
					}, nil)
			},
			status: http.StatusNoContent,
			check: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				cookies := recorder.Result().Cookies()

				require.Len(t, cookies, 2)

				sessionCookie := cookies[0]
				if cookies[0].Name == "iam_refresh" {
					sessionCookie = cookies[1]
				}
				assert.Equal(t, "iam_session", sessionCookie.Name)
				assert.Equal(t, "session-123", sessionCookie.Value)
				assert.True(t, sessionCookie.HttpOnly)
				assert.Equal(t, "/", sessionCookie.Path)
				assert.Equal(t, int((24 * time.Hour).Seconds()), sessionCookie.MaxAge)

				refreshCookie := cookies[0]
				if cookies[0].Name == "iam_session" {
					refreshCookie = cookies[1]
				}
				assert.Equal(t, "iam_refresh", refreshCookie.Name)
				assert.Equal(t, "refresh-456", refreshCookie.Value)
				assert.True(t, refreshCookie.HttpOnly)
				assert.Equal(t, "/api/1/auth/session/refresh", refreshCookie.Path)
				assert.Equal(t, int((24 * time.Hour).Seconds()), refreshCookie.MaxAge)
			},
		},
		{
			name: "invalid_code",
			setupMock: func(oauthUC *oauthmocks.MockUsecase) {
				oauthUC.EXPECT().
					ExchangeAuthCode(gomock.Any(), oauthdto.ExchangeAuthCodeIn{
						Code: "one-time-code",
					}).
					Return(nil, apperror.InvalidAuthCode(nil))
			},
			status: http.StatusBadRequest,
			check: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				var payload map[string]map[string]string

				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
				assert.Equal(t, "invalid-auth-code", payload["error"]["code"])
				assert.NotEmpty(t, payload["error"]["message"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			e := echo.New()
			oauthUC := oauthmocks.NewMockUsecase(ctrl)
			sessionUC := sessionmocks.NewMockUsecase(ctrl)

			tt.setupMock(oauthUC)

			handler := NewHandler(
				oauthUC,
				sessionUC,
				config.AuthConfig{
					SessionTTL: 24 * time.Hour,
					RefreshTTL: 24 * time.Hour,
				},
			)

			request := httptest.NewRequest(
				http.MethodPost,
				"/api/1/auth/code/exchange",
				strings.NewReader(`{"code":"one-time-code"}`),
			)
			request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

			recorder := httptest.NewRecorder()

			err := handler.ExchangeAuthCode(e.NewContext(request, recorder))

			require.NoError(t, err)
			assert.Equal(t, tt.status, recorder.Code)
			tt.check(t, recorder)
		})
	}
}

func TestHandlerGetCurrentSession(t *testing.T) {
	tests := []struct {
		name      string
		cookie    string
		setupMock func(sessionUC *sessionmocks.MockUsecase)
		status    int
		check     func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name:   "valid_session",
			cookie: "iam_session=session-id",
			setupMock: func(sessionUC *sessionmocks.MockUsecase) {
				sessionUC.EXPECT().
					GetCurrentSession(gomock.Any(), sessiondto.GetCurrentSessionIn{
						SessionID: "session-id",
					}).
					Return(&sessiondto.GetCurrentSessionOut{
						Account: accountdomain.Account{
							ID:     42,
							Email:  "user@example.com",
							Status: accountdomain.StatusActive,
						},
					}, nil)
			},
			status: http.StatusOK,
			check: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				var payload map[string]any

				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
				assert.Equal(t, float64(42), payload["account_id"])
				assert.Equal(t, "user@example.com", payload["email"])
				assert.Equal(t, "active", payload["status"])
			},
		},
		{
			name: "missing_cookie",
			setupMock: func(sessionUC *sessionmocks.MockUsecase) {
				sessionUC.EXPECT().
					GetCurrentSession(gomock.Any(), sessiondto.GetCurrentSessionIn{
						SessionID: "",
					}).
					Return(nil, apperror.MissingSession())
			},
			status: http.StatusUnauthorized,
			check: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				var payload map[string]map[string]string

				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
				assert.Equal(t, "missing-session", payload["error"]["code"])
			},
		},
		{
			name:   "expired_session",
			cookie: "iam_session=expired",
			setupMock: func(sessionUC *sessionmocks.MockUsecase) {
				sessionUC.EXPECT().
					GetCurrentSession(gomock.Any(), sessiondto.GetCurrentSessionIn{
						SessionID: "expired",
					}).
					Return(nil, apperror.ExpiredSession())
			},
			status: http.StatusUnauthorized,
			check: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				var payload map[string]map[string]string

				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
				assert.Equal(t, "expired-session", payload["error"]["code"])
			},
		},
		{
			name:   "blocked_account",
			cookie: "iam_session=blocked",
			setupMock: func(sessionUC *sessionmocks.MockUsecase) {
				sessionUC.EXPECT().
					GetCurrentSession(gomock.Any(), sessiondto.GetCurrentSessionIn{
						SessionID: "blocked",
					}).
					Return(nil, apperror.AccountBlocked())
			},
			status: http.StatusForbidden,
			check: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				var payload map[string]map[string]string

				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
				assert.Equal(t, "account-blocked", payload["error"]["code"])
			},
		},
		{
			name:   "deleted_account",
			cookie: "iam_session=deleted",
			setupMock: func(sessionUC *sessionmocks.MockUsecase) {
				sessionUC.EXPECT().
					GetCurrentSession(gomock.Any(), sessiondto.GetCurrentSessionIn{
						SessionID: "deleted",
					}).
					Return(nil, apperror.AccountDeleted())
			},
			status: http.StatusForbidden,
			check: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				var payload map[string]map[string]string

				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
				assert.Equal(t, "account-deleted", payload["error"]["code"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			e := echo.New()
			oauthUC := oauthmocks.NewMockUsecase(ctrl)
			sessionUC := sessionmocks.NewMockUsecase(ctrl)

			tt.setupMock(sessionUC)

			handler := NewHandler(
				oauthUC,
				sessionUC,
				config.AuthConfig{},
			)

			request := httptest.NewRequest(http.MethodGet, "/api/1/auth/me", nil)
			if tt.cookie != "" {
				request.Header.Set(echo.HeaderCookie, tt.cookie)
			}

			recorder := httptest.NewRecorder()

			err := handler.GetCurrentSession(e.NewContext(request, recorder))

			require.NoError(t, err)
			assert.Equal(t, tt.status, recorder.Code)
			tt.check(t, recorder)
		})
	}
}

func TestHandlerLogout(t *testing.T) {
	tests := []struct {
		name      string
		cookie    string
		sessionID string
		setupMock func(sessionUC *sessionmocks.MockUsecase, sessionID string)
		status    int
		check     func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name:      "valid_session",
			cookie:    "iam_session=session-id",
			sessionID: "session-id",
			setupMock: func(sessionUC *sessionmocks.MockUsecase, sessionID string) {
				sessionUC.EXPECT().
					Logout(gomock.Any(), sessiondto.LogoutIn{
						SessionID:    sessionID,
						RefreshToken: "",
					}).
					Return(&sessiondto.LogoutOut{}, nil)
			},
			status: http.StatusNoContent,
			check: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				cookies := recorder.Result().Cookies()

				require.Len(t, cookies, 2)

				sessionCookie := cookies[0]
				if cookies[0].Name == "iam_refresh" {
					sessionCookie = cookies[1]
				}
				assert.Equal(t, "iam_session", sessionCookie.Name)
				assert.Equal(t, "", sessionCookie.Value)
				assert.Equal(t, -1, sessionCookie.MaxAge)

				refreshCookie := cookies[0]
				if cookies[0].Name == "iam_session" {
					refreshCookie = cookies[1]
				}
				assert.Equal(t, "iam_refresh", refreshCookie.Name)
				assert.Equal(t, "", refreshCookie.Value)
				assert.Equal(t, -1, refreshCookie.MaxAge)
			},
		},
		{
			name:      "missing_session",
			sessionID: "",
			setupMock: func(sessionUC *sessionmocks.MockUsecase, sessionID string) {
				sessionUC.EXPECT().
					Logout(gomock.Any(), sessiondto.LogoutIn{
						SessionID:    sessionID,
						RefreshToken: "",
					}).
					Return(&sessiondto.LogoutOut{}, nil)
			},
			status: http.StatusNoContent,
			check: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				cookies := recorder.Result().Cookies()

				require.Len(t, cookies, 2)

				sessionCookie := cookies[0]
				if cookies[0].Name == "iam_refresh" {
					sessionCookie = cookies[1]
				}
				assert.Equal(t, "iam_session", sessionCookie.Name)
				assert.Equal(t, -1, sessionCookie.MaxAge)

				refreshCookie := cookies[0]
				if cookies[0].Name == "iam_session" {
					refreshCookie = cookies[1]
				}
				assert.Equal(t, "iam_refresh", refreshCookie.Name)
				assert.Equal(t, -1, refreshCookie.MaxAge)
			},
		},
		{
			name:      "already_expired_session",
			cookie:    "iam_session=expired",
			sessionID: "expired",
			setupMock: func(sessionUC *sessionmocks.MockUsecase, sessionID string) {
				sessionUC.EXPECT().
					Logout(gomock.Any(), sessiondto.LogoutIn{
						SessionID:    sessionID,
						RefreshToken: "",
					}).
					Return(&sessiondto.LogoutOut{}, nil)
			},
			status: http.StatusNoContent,
			check: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				cookies := recorder.Result().Cookies()

				require.Len(t, cookies, 2)

				sessionCookie := cookies[0]
				if cookies[0].Name == "iam_refresh" {
					sessionCookie = cookies[1]
				}
				assert.Equal(t, "iam_session", sessionCookie.Name)
				assert.Equal(t, -1, sessionCookie.MaxAge)

				refreshCookie := cookies[0]
				if cookies[0].Name == "iam_session" {
					refreshCookie = cookies[1]
				}
				assert.Equal(t, "iam_refresh", refreshCookie.Name)
				assert.Equal(t, -1, refreshCookie.MaxAge)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			e := echo.New()
			oauthUC := oauthmocks.NewMockUsecase(ctrl)
			sessionUC := sessionmocks.NewMockUsecase(ctrl)

			tt.setupMock(sessionUC, tt.sessionID)

			handler := NewHandler(
				oauthUC,
				sessionUC,
				config.AuthConfig{},
			)

			request := httptest.NewRequest(http.MethodPost, "/api/1/auth/logout", nil)
			if tt.cookie != "" {
				request.Header.Set(echo.HeaderCookie, tt.cookie)
			}

			recorder := httptest.NewRecorder()

			err := handler.Logout(e.NewContext(request, recorder))

			require.NoError(t, err)
			assert.Equal(t, tt.status, recorder.Code)
			tt.check(t, recorder)
		})
	}
}
