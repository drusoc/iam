package auth

import (
	"log/slog"
	"net/http"
	"net/url"

	"iam/internal/apperror"
	"iam/internal/config"
	transportresponse "iam/internal/transport/http/response"
	oauthusecase "iam/internal/usecase/oauth"
	oauthdto "iam/internal/usecase/oauth/dto"
	sessionusecase "iam/internal/usecase/session"
	sessiondto "iam/internal/usecase/session/dto"

	"github.com/labstack/echo/v4"
)

type Handler struct {
	oauth       oauthusecase.Usecase
	session     sessionusecase.Usecase
	appErrorURL string
	sessionTTL  int
	refreshTTL  int
	refreshPath string
}

func NewHandler(oauthUsecase oauthusecase.Usecase, sessionUsecase sessionusecase.Usecase, cfg config.AuthConfig) *Handler {
	return &Handler{
		oauth:       oauthUsecase,
		session:     sessionUsecase,
		appErrorURL: cfg.ErrorURL,
		sessionTTL:  int(cfg.SessionTTL.Seconds()),
		refreshTTL:  int(cfg.RefreshTTL.Seconds()),
		refreshPath: "/api/1/auth/session/refresh",
	}
}

func (h *Handler) Register(e *echo.Echo) {
	e.GET("/api/1/auth/google/start", h.StartGoogleAuth)
	e.GET("/api/1/auth/google/callback", h.HandleGoogleCallback)
	e.POST("/api/1/auth/code/exchange", h.ExchangeAuthCode)
	e.GET("/api/1/auth/me", h.GetCurrentSession)
	e.POST("/api/1/auth/logout", h.Logout)
	e.POST("/api/1/auth/session/refresh", h.Refresh)
}

func (h *Handler) StartGoogleAuth(c echo.Context) error {
	slog.Debug("start google auth",
		slog.String("path", c.Request().URL.Path),
	)

	response, err := h.oauth.StartGoogleAuth(c.Request().Context(), oauthdto.StartGoogleAuthIn{})
	if err != nil {
		slog.Error("start google auth",
			slog.Any("error", err),
			slog.String("path", c.Request().URL.Path),
		)
		return err
	}
	if response == nil {
		slog.Error("start google auth",
			slog.String("error", "nil response"),
			slog.String("path", c.Request().URL.Path),
		)
		return writeError(c, apperror.Internal(nil))
	}

	slog.Info("google auth started",
		slog.String("redirect_url", response.RedirectURL),
		slog.String("state", response.State[:8]+"..."),
	)
	return c.Redirect(http.StatusFound, response.RedirectURL)
}

func (h *Handler) HandleGoogleCallback(c echo.Context) error {
	slog.Debug("handle google callback",
		slog.String("path", c.Request().URL.Path),
		slog.Bool("has_code", c.QueryParam("code") != ""),
		slog.Bool("has_state", c.QueryParam("state") != ""),
	)

	response, err := h.oauth.HandleGoogleCallback(c.Request().Context(), oauthdto.HandleGoogleCallbackIn{
		Code:  c.QueryParam("code"),
		State: c.QueryParam("state"),
	})
	if err != nil {
		slog.Error("handle google callback",
			slog.Any("error", err),
			slog.String("path", c.Request().URL.Path),
		)
		redirectURL, redirectErr := withError(h.appErrorURL, callbackErrorCode(err))
		if redirectErr != nil {
			slog.Error("build redirect url",
				slog.Any("error", redirectErr),
			)
			return writeError(c, apperror.Internal(redirectErr))
		}
		slog.Info("redirect to error",
			slog.String("url", redirectURL),
			slog.String("code", callbackErrorCode(err)),
		)
		return c.Redirect(http.StatusFound, redirectURL)
	}
	if response == nil {
		slog.Error("handle google callback",
			slog.String("error", "nil response"),
			slog.String("path", c.Request().URL.Path),
		)
		return writeError(c, apperror.Internal(nil))
	}
	slog.Info("redirect to success",
		slog.String("url", response.RedirectURL),
	)
	return c.Redirect(http.StatusFound, response.RedirectURL)
}

func (h *Handler) ExchangeAuthCode(c echo.Context) error {
	slog.Debug("exchange auth code",
		slog.String("path", c.Request().URL.Path),
		slog.String("method", c.Request().Method),
	)

	request := oauthdto.ExchangeAuthCodeIn{}
	if err := c.Bind(&request); err != nil {
		slog.Error("bind request",
			slog.Any("error", err),
			slog.String("path", c.Request().URL.Path),
		)
		return writeError(c, apperror.InvalidRequestBody(err))
	}

	response, err := h.oauth.ExchangeAuthCode(c.Request().Context(), request)
	if err != nil {
		slog.Error("exchange auth code",
			slog.Any("error", err),
			slog.String("path", c.Request().URL.Path),
		)
		return writeError(c, err)
	}
	if response == nil {
		slog.Error("exchange auth code",
			slog.String("error", "nil response"),
			slog.String("path", c.Request().URL.Path),
		)
		return writeError(c, apperror.Internal(nil))
	}

	c.SetCookie(&http.Cookie{
		Name:     "iam_session",
		Value:    response.SessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   h.sessionTTL,
	})

	c.SetCookie(&http.Cookie{
		Name:     "iam_refresh",
		Value:    response.RefreshToken,
		Path:     h.refreshPath,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   h.refreshTTL,
	})

	slog.Info("auth successful",
		slog.String("session_id", response.SessionID[:8]+"..."),
	)
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) GetCurrentSession(c echo.Context) error {
	slog.Debug("get current session",
		slog.String("path", c.Request().URL.Path),
		slog.Bool("has_session_cookie", sessionCookie(c) != ""),
	)

	response, err := h.session.GetCurrentSession(c.Request().Context(), sessiondto.GetCurrentSessionIn{
		SessionID: sessionCookie(c),
	})
	if err != nil {
		slog.Error("get current session",
			slog.Any("error", err),
			slog.String("path", c.Request().URL.Path),
		)
		return writeError(c, err)
	}
	if response == nil {
		slog.Error("get current session",
			slog.String("error", "nil response"),
			slog.String("path", c.Request().URL.Path),
		)
		return writeError(c, apperror.Internal(nil))
	}

	slog.Info("session retrieved",
		slog.Int64("account_id", response.Account.ID),
		slog.String("email", response.Account.Email),
		slog.String("status", string(response.Account.Status)),
	)
	return c.JSON(http.StatusOK, map[string]any{
		"account_id": response.Account.ID,
		"email":      response.Account.Email,
		"status":     response.Account.Status,
	})
}

func (h *Handler) Logout(c echo.Context) error {
	slog.Debug("logout",
		slog.String("path", c.Request().URL.Path),
		slog.Bool("has_session_cookie", sessionCookie(c) != ""),
		slog.Bool("has_refresh_cookie", refreshCookie(c) != ""),
	)

	_, err := h.session.Logout(c.Request().Context(), sessiondto.LogoutIn{
		SessionID:    sessionCookie(c),
		RefreshToken: refreshCookie(c),
	})
	if err != nil {
		slog.Error("logout",
			slog.Any("error", err),
			slog.String("path", c.Request().URL.Path),
		)
		return writeError(c, err)
	}

	clearSessionCookie(c)
	clearRefreshCookie(c)

	slog.Info("logout successful")
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) Refresh(c echo.Context) error {
	slog.Debug("refresh session",
		slog.String("path", c.Request().URL.Path),
		slog.Bool("has_refresh_cookie", refreshCookie(c) != ""),
	)

	response, err := h.session.Refresh(c.Request().Context(), sessiondto.RefreshIn{
		RefreshToken: refreshCookie(c),
	})
	if err != nil {
		slog.Error("refresh session",
			slog.Any("error", err),
			slog.String("path", c.Request().URL.Path),
		)
		clearSessionCookie(c)
		clearRefreshCookie(c)
		return writeError(c, err)
	}
	if response == nil {
		slog.Error("refresh session",
			slog.String("error", "nil response"),
			slog.String("path", c.Request().URL.Path),
		)
		clearSessionCookie(c)
		clearRefreshCookie(c)
		return writeError(c, apperror.Internal(nil))
	}

	c.SetCookie(&http.Cookie{
		Name:     "iam_session",
		Value:    response.SessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   h.sessionTTL,
	})

	c.SetCookie(&http.Cookie{
		Name:     "iam_refresh",
		Value:    response.RefreshToken,
		Path:     h.refreshPath,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   h.refreshTTL,
	})

	slog.Info("session refreshed",
		slog.String("session_id", response.SessionID[:8]+"..."),
	)
	return c.NoContent(http.StatusNoContent)
}

func sessionCookie(c echo.Context) string {
	cookie, err := c.Cookie("iam_session")
	if err != nil {
		return ""
	}

	return cookie.Value
}

func refreshCookie(c echo.Context) string {
	cookie, err := c.Cookie("iam_refresh")
	if err != nil {
		return ""
	}

	return cookie.Value
}

func clearSessionCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     "iam_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func clearRefreshCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     "iam_refresh",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func callbackErrorCode(err error) string {
	appErr, ok := apperror.As(err)
	if !ok {
		return "internal-error"
	}

	return appErr.Code()
}

func writeError(c echo.Context, err error) error {
	appErr, ok := apperror.As(err)
	if !ok {
		appErr = apperror.Internal(err)
	}

	return c.JSON(
		appErr.Status(),
		transportresponse.NewError(
			appErr.Message(),
			appErr.Code(),
		),
	)
}

func withError(rawURL, errorCode string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	query := parsedURL.Query()
	query.Set("error", errorCode)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}
