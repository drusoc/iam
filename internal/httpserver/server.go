package httpserver

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Registrar interface {
	Register(e *echo.Echo)
}

func New(registrars ...Registrar) *echo.Echo {
	e := echo.New()
	e.Use(middleware.RequestID())
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())
	e.GET("/healthz", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	for _, registrar := range registrars {
		registrar.Register(e)
	}

	return e
}
