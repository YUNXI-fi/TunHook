package web

import (
	"encoding/json"
	"net/http"
	"strconv"

	"go.uber.org/zap"

	"tunhook/errpage"
)

// errorPageView 设置页一份错误页模板：状态码 + 模板文件路径 + 当前 HTML 内容。
type errorPageView struct {
	Code int    `json:"code"` // HTTP 状态码
	File string `json:"file"` // 模板文件绝对路径（可直接用编辑器打开修改）
	HTML string `json:"html"` // 当前模板内容
}

// errorPageViews 按 Codes 顺序组装九个状态码的模板视图。
func errorPageViews() []errorPageView {
	out := make([]errorPageView, 0, len(errpage.Codes))
	for _, code := range errpage.Codes {
		content, _ := errpage.Content(code)
		out = append(out, errorPageView{Code: code, File: errpage.File(code), HTML: content})
	}
	return out
}

// handleErrorPagesGet 返回九个状态码当前生效的模板内容。
func (s *Server) handleErrorPagesGet(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, apiOK(errorPageViews()))
}

// handleErrorPagesPost 保存错误页模板：{code, html} 写入单份模板文件并立即生效；
// {reset:true} 把九份模板恢复为内置默认内容。模板文件即持久化，无需写回数据库。
func (s *Server) handleErrorPagesPost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reset bool   `json:"reset"`
		Code  int    `json:"code"`
		HTML  string `json:"html"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}

	if req.Reset {
		if err := errpage.Reset(); err != nil {
			s.logger.Error("重置错误页模板失败")
			s.writeJSON(w, http.StatusInternalServerError, apiErr("重置失败："+err.Error()))
			return
		}
		s.logger.Info("错误页模板已恢复内置默认")
		s.writeJSON(w, http.StatusOK, apiOK(errorPageViews()))
		return
	}

	if err := errpage.Save(req.Code, req.HTML); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("保存失败："+err.Error()))
		return
	}

	s.logger.Info("错误页模板已更新", zap.Int("code", req.Code))
	s.writeJSON(w, http.StatusOK, apiOK(errorPageViews()))
}

// handleErrorPagesPreview 按指定状态码渲染当前模板，供设置页「访问」按钮预览：
// 与访客看到的错误页完全一致（同样的状态码、同样的响应头）。
func (s *Server) handleErrorPagesPreview(w http.ResponseWriter, r *http.Request) {
	code, err := strconv.Atoi(r.URL.Query().Get("code"))
	if err != nil || !errpage.Preview(w, code) {
		s.writeJSON(w, http.StatusBadRequest, apiErr("不支持的错误状态码"))
	}
}
