/**
 * Gin 中间件：CORS 与预检处理
 */
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

/**
 * OptionsBypass 直接放行 OPTIONS 预检请求，避免触发鉴权或业务逻辑
 * @returns gin.HandlerFunc - Gin 中间件函数
 */
func OptionsBypass() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodOptions {
			c.Next()
			return
		}

		origin := c.GetHeader("Origin")
		if origin == "" {
			origin = "*"
		}
		allowMethods := c.GetHeader("Access-Control-Request-Method")
		if allowMethods == "" {
			allowMethods = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
		}
		allowHeaders := c.GetHeader("Access-Control-Request-Headers")
		if allowHeaders == "" {
			allowHeaders = "Authorization, Content-Type"
		}

		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Vary", "Origin")
		c.Header("Access-Control-Allow-Methods", allowMethods)
		c.Header("Access-Control-Allow-Headers", allowHeaders)
		c.Header("Access-Control-Max-Age", "86400")
		c.Status(http.StatusNoContent)
		c.Abort()
	}
}

/**
 * CORSAllowOrigin 确保所有响应都包含 Access-Control-Allow-Origin
 * @returns gin.HandlerFunc - Gin 中间件函数
 */
func CORSAllowOrigin() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			origin = "*"
		}
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Vary", "Origin")
		c.Next()
	}
}
