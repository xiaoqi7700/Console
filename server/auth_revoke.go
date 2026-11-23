package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
)

// 审计 B1 短期缓解：JWT 签发时带 jti，提供会话吊销机制——此前唯一的
// 「踢会话」手段是改密码（轮换签名 key）。token 泄露后管理员不想改密码时，
// 没有办法让已签发的 7 天 token 失效。
//
// 存储走 settings 表两行，不建新表：
//   - auth_revoke_all_before：哨兵时间戳（unix 秒），iat 早于它的 token 全部失效。
//     这是「吊销所有会话」的主实现，也覆盖无 jti 的历史 token。
//   - auth_revoked_jtis：JSON 数组 [{"jti":..,"at":unix}]，逐会话吊销。
//     单用户系统吊销频率极低，token 7 天 TTL 后自然无效，读时内存修剪即可，
//     行不会膨胀。
//
// 校验挂在 requireAuth：签名/过期通过后查内存缓存（30s TTL 从 settings 刷新，
// 写端点主动更新），避免每个请求打一次数据库。settings 读失败时沿用缓存旧值
// 放行（fail-open）——吊销是纵深防御，不该让它把签名合法的正常请求挡在门外。

const (
	authRevokeAllBeforeKey = "auth_revoke_all_before"
	authRevokedJtisKey     = "auth_revoked_jtis"

	revocationRefreshInterval = 30 * time.Second
)

type revokedJti struct {
	JTI string `json:"jti"`
	At  int64  `json:"at"` // unix 秒，仅用于修剪
}

type revocationCache struct {
	mu     sync.Mutex
	before int64           // 哨兵：iat < before 的 token 全部失效
	jtis   map[string]bool // 已吊销的 jti 集合
	loaded time.Time       // 上次从 settings 刷新的时间
}

func (s *Server) revocations() *revocationCache {
	s.revokeCacheOnce.Do(func() { s.revokeCache = &revocationCache{jtis: map[string]bool{}} })
	return s.revokeCache
}

// refreshIfStale 超过刷新间隔时从 settings 重读。读失败沿用旧值（fail-open），
// loaded 仍推进——DB 故障期间不要每个请求都去撞一次。
func (c *revocationCache) refreshIfStale(pg *db.DB) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded.IsZero() && time.Since(c.loaded) < revocationRefreshInterval {
		return
	}
	before, _, err := pg.GetSetting(authRevokeAllBeforeKey)
	if err == nil {
		if v, perr := strconv.ParseInt(before, 10, 64); perr == nil {
			c.before = v
		} else if before == "" {
			c.before = 0
		}
	}
	if raw, _, err := pg.GetSetting(authRevokedJtisKey); err == nil {
		list := parseRevokedJtis(raw)
		jtis := make(map[string]bool, len(list))
		for _, e := range list {
			jtis[e.JTI] = true
		}
		c.jtis = jtis
	}
	c.loaded = time.Now()
}

// revoked reports whether a token with these claims must be rejected.
// 哨兵用 iat <= before：吊销请求与新签发落在同一秒时无法区分先后，
// 一律按已吊销处理（fail-closed），重新登录即恢复。
func (c *revocationCache) revoked(jti string, iat int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.before > 0 && iat > 0 && iat <= c.before {
		return true
	}
	return jti != "" && c.jtis[jti]
}

// update 直接更新内存缓存（写端点在持久化成功后调用，立即可见，不等 30s 刷新）。
func (c *revocationCache) update(before int64, jti string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if before > 0 {
		c.before = before
	}
	if jti != "" {
		c.jtis[jti] = true
	}
	c.loaded = time.Now()
}

func parseRevokedJtis(raw string) []revokedJti {
	if raw == "" {
		return nil
	}
	var list []revokedJti
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil
	}
	// 修剪：超过 token TTL 的吊销记录没有意义（token 本来就过期了）。
	cutoff := time.Now().Add(-jwtTTL).Unix()
	kept := list[:0]
	for _, e := range list {
		if e.At >= cutoff && e.JTI != "" {
			kept = append(kept, e)
		}
	}
	return kept
}

// parseTokenClaims 签名校验通过后取回 claims（iat/jti），供吊销检查与会话标识。
// 注意 jwt v5 Parse 的 Claims 落成 MapClaims（不是签发用的 RegisteredClaims）。
func parseTokenClaims(tokenStr string, key []byte) (iat int64, jti string, ok bool) {
	t, err := parseJWT(tokenStr, key)
	if err != nil {
		return 0, "", false
	}
	cl, okClaims := t.Claims.(jwt.MapClaims)
	if !okClaims {
		return 0, "", false
	}
	if f, okF := cl["iat"].(float64); okF {
		iat = int64(f)
	}
	jti, _ = cl["jti"].(string)
	return iat, jti, true
}

// POST /api/sessions/revoke-all — 吊销当前所有已签发会话（含调用者自己）。
// 写哨兵时间戳，iat 早于它的 token 在 requireAuth 全部被拒。旧 token 没有 jti
// 也能被哨兵覆盖。管理面危险操作，要求显式 confirm 标志（审计 B1 二次确认）。
func (s *Server) sessionRevokeAll(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if _, _, ok := parseTokenClaims(extractToken(r), s.currentJWTKey()); !ok {
		writeErr(w, 401, "未授权")
		return
	}
	var req struct {
		Confirm bool `json:"confirm"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if !req.Confirm {
		writeErr(w, 400, "缺少确认标志：请求体需携带 {\"confirm\":true}（该操作会登出所有会话，包括当前会话）")
		return
	}
	now := time.Now().Unix()
	if err := pg.SetSetting(authRevokeAllBeforeKey, strconv.FormatInt(now, 10)); err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	s.revocations().update(now, "")
	writeJSON(w, 200, map[string]any{"ok": true, "revoked_before": now})
}

// POST /api/sessions/revoke-current — 吊销调用方当前会话（单设备登出）。
// 历史 token（无 jti）无法逐个吊销，提示走 revoke-all。
func (s *Server) sessionRevokeCurrent(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	_, jti, ok := parseTokenClaims(extractToken(r), s.currentJWTKey())
	if !ok {
		writeErr(w, 401, "未授权")
		return
	}
	if jti == "" {
		writeErr(w, 400, "当前会话无会话标识（旧版签发的 token），请改用「吊销所有会话」或修改密码")
		return
	}
	raw, _, err := pg.GetSetting(authRevokedJtisKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	list := parseRevokedJtis(raw)
	list = append(list, revokedJti{JTI: jti, At: time.Now().Unix()})
	b, err := json.Marshal(list)
	if err != nil {
		writeErr(w, 500, "序列化失败")
		return
	}
	if err := pg.SetSetting(authRevokedJtisKey, string(b)); err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	s.revocations().update(0, jti)
	writeJSON(w, 200, map[string]any{"ok": true})
}
