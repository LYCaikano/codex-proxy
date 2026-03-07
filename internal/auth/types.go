/**
 * 账号认证类型定义模块
 * 定义 Codex Token 数据结构、账号文件存储格式和运行时认证状态
 */
package auth

import (
	"sync"
	"sync/atomic"
	"time"
)

/**
 * TokenData 保存从 OpenAI OAuth 获取的 Token 信息
 * @field IDToken - JWT ID Token，包含用户声明
 * @field AccessToken - OAuth2 访问令牌
 * @field RefreshToken - 用于获取新访问令牌的刷新令牌
 * @field AccountID - OpenAI 账号标识符
 * @field Email - 账号邮箱
 * @field Expire - 访问令牌过期时间戳（RFC3339格式）
 */
type TokenData struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccountID    string `json:"account_id"`
	Email        string `json:"email"`
	Expire       string `json:"expired"`
	PlanType     string `json:"plan_type,omitempty"`
}

/**
 * TokenFile 表示磁盘上的账号文件结构
 * @field IDToken - JWT ID Token
 * @field AccessToken - 访问令牌
 * @field RefreshToken - 刷新令牌
 * @field AccountID - 账号ID
 * @field LastRefresh - 上次刷新时间戳
 * @field Email - 邮箱
 * @field Type - 认证类型，固定为 "codex"
 * @field Expire - Token 过期时间
 */
type TokenFile struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccountID    string `json:"account_id"`
	LastRefresh  string `json:"last_refresh"`
	Email        string `json:"email"`
	Type         string `json:"type"`
	Expire       string `json:"expired"`
}

/**
 * Account 表示运行时的单个 Codex 账号状态
 * @field mu - 并发保护锁
 * @field FilePath - 账号文件路径
 * @field Token - 当前 Token 数据
 * @field Status - 账号状态（active/cooldown/disabled）
 * @field LastError - 最近一次错误
 * @field LastRefreshedAt - 上次成功刷新时间
 * @field NextRetryAfter - 下次允许重试的时间
 * @field CooldownUntil - 冷却结束时间
 * @field ConsecutiveFailures - 连续失败次数
 * @field LastUsedAt - 最后一次使用时间
 * @field TotalRequests - 总请求数（原子操作）
 * @field TotalErrors - 总错误数（原子操作）
 * @field DisableReason - 禁用原因编码
 */
type Account struct {
	mu                  sync.RWMutex
	FilePath            string
	Token               TokenData
	Status              AccountStatus
	LastError           error
	LastRefreshedAt     time.Time
	NextRetryAfter      time.Time
	CooldownUntil       time.Time
	ConsecutiveFailures int
	LastUsedAt          time.Time
	TotalRequests       atomic.Int64
	TotalErrors         atomic.Int64
	DisableReason       string
	QuotaResetsAt       time.Time
	QuotaExhausted      bool
}

/**
 * AccountStatus 账号状态枚举
 */
type AccountStatus int

const (
	/* StatusActive 账号正常可用 */
	StatusActive AccountStatus = iota
	/* StatusCooldown 账号冷却中（限频等） */
	StatusCooldown
	/* StatusDisabled 账号已禁用（刷新失败等） */
	StatusDisabled
)

/* 禁用原因编码 */
const (
	ReasonNone           = ""
	ReasonAuth401        = "auth_401"
	ReasonAuth403        = "auth_403"
	ReasonQuotaExhausted = "quota_exhausted"
	ReasonRefreshFailed  = "refresh_failed"
	ReasonHealthCheck    = "health_check_failed"
)

/**
 * AccountStats 账号统计信息（只读快照）
 * @field Email - 账号邮箱
 * @field Status - 当前状态
 * @field DisableReason - 禁用原因
 * @field TotalRequests - 总请求数
 * @field TotalErrors - 总错误数
 * @field ConsecutiveFailures - 连续失败次数
 * @field LastUsedAt - 最后使用时间
 * @field CooldownUntil - 冷却结束时间
 */
type AccountStats struct {
	Email               string    `json:"email"`
	FilePath            string    `json:"file_path"`
	Status              string    `json:"status"`
	PlanType            string    `json:"plan_type,omitempty"`
	DisableReason       string    `json:"disable_reason,omitempty"`
	TotalRequests       int64     `json:"total_requests"`
	TotalErrors         int64     `json:"total_errors"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastUsedAt          time.Time `json:"last_used_at,omitempty"`
	LastRefreshedAt     time.Time `json:"last_refreshed_at,omitempty"`
	CooldownUntil       time.Time `json:"cooldown_until,omitempty"`
	QuotaExhausted      bool      `json:"quota_exhausted"`
	QuotaResetsAt       time.Time `json:"quota_resets_at,omitempty"`
	TokenExpire         string    `json:"token_expire,omitempty"`
}

/**
 * IsAvailable 检查账号当前是否可用
 * @returns bool - 如果账号状态为 active 或冷却已过则返回 true
 */
func (a *Account) IsAvailable() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.Status == StatusDisabled {
		return false
	}
	if a.Status == StatusCooldown && time.Now().Before(a.CooldownUntil) {
		return false
	}
	return true
}

/**
 * GetAccessToken 安全获取当前的 AccessToken
 * @returns string - 当前 AccessToken
 */
func (a *Account) GetAccessToken() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Token.AccessToken
}

/**
 * GetAccountID 安全获取当前的 AccountID
 * @returns string - 当前 AccountID
 */
func (a *Account) GetAccountID() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Token.AccountID
}

/**
 * GetEmail 安全获取当前的 Email
 * @returns string - 当前 Email
 */
func (a *Account) GetEmail() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Token.Email
}

/**
 * UpdateToken 安全更新 Token 数据
 * @param td - 新的 Token 数据
 */
func (a *Account) UpdateToken(td TokenData) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Token = td
	a.LastRefreshedAt = time.Now()
	a.Status = StatusActive
	a.LastError = nil
}

/**
 * SetCooldown 将账号设为冷却状态
 * @param duration - 冷却持续时间
 */
func (a *Account) SetCooldown(duration time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Status = StatusCooldown
	a.CooldownUntil = time.Now().Add(duration)
}

/**
 * SetQuotaCooldown 设置配额耗尽冷却（429 限频）
 * @param duration - 冷却持续时间
 */
func (a *Account) SetQuotaCooldown(duration time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Status = StatusCooldown
	a.CooldownUntil = time.Now().Add(duration)
	a.QuotaExhausted = true
	a.QuotaResetsAt = time.Now().Add(duration)
}

/**
 * SetDisabled 将账号标记为禁用
 * @param err - 禁用原因
 */
func (a *Account) SetDisabled(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Status = StatusDisabled
	a.LastError = err
}

/**
 * SetDisabledWithReason 将账号标记为禁用，并记录原因编码
 * @param err - 禁用原因
 * @param reason - 原因编码
 */
func (a *Account) SetDisabledWithReason(err error, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Status = StatusDisabled
	a.LastError = err
	a.DisableReason = reason
}

/**
 * SetActive 恢复账号为可用状态
 */
func (a *Account) SetActive() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Status = StatusActive
	a.LastError = nil
	a.ConsecutiveFailures = 0
	a.DisableReason = ReasonNone
	a.QuotaExhausted = false
	a.QuotaResetsAt = time.Time{}
}

/**
 * RecordSuccess 记录一次成功请求
 */
func (a *Account) RecordSuccess() {
	a.TotalRequests.Add(1)
	a.mu.Lock()
	a.ConsecutiveFailures = 0
	a.LastUsedAt = time.Now()
	a.mu.Unlock()
}

/**
 * RecordFailure 记录一次失败请求
 * @returns int - 当前连续失败次数
 */
func (a *Account) RecordFailure() int {
	a.TotalRequests.Add(1)
	a.TotalErrors.Add(1)
	a.mu.Lock()
	a.ConsecutiveFailures++
	a.LastUsedAt = time.Now()
	failures := a.ConsecutiveFailures
	a.mu.Unlock()
	return failures
}

/**
 * GetStats 获取账号统计信息快照
 * @returns AccountStats - 统计快照
 */
func (a *Account) GetStats() AccountStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	statusStr := "active"
	switch a.Status {
	case StatusCooldown:
		statusStr = "cooldown"
	case StatusDisabled:
		statusStr = "disabled"
	}

	/* 配额状态：如果已过期则自动恢复 */
	quotaExhausted := a.QuotaExhausted
	quotaResetsAt := a.QuotaResetsAt
	if quotaExhausted && !quotaResetsAt.IsZero() && time.Now().After(quotaResetsAt) {
		quotaExhausted = false
	}

	return AccountStats{
		Email:               a.Token.Email,
		FilePath:            a.FilePath,
		Status:              statusStr,
		PlanType:            a.Token.PlanType,
		DisableReason:       a.DisableReason,
		TotalRequests:       a.TotalRequests.Load(),
		TotalErrors:         a.TotalErrors.Load(),
		ConsecutiveFailures: a.ConsecutiveFailures,
		LastUsedAt:          a.LastUsedAt,
		LastRefreshedAt:     a.LastRefreshedAt,
		CooldownUntil:       a.CooldownUntil,
		QuotaExhausted:      quotaExhausted,
		QuotaResetsAt:       quotaResetsAt,
		TokenExpire:         a.Token.Expire,
	}
}
