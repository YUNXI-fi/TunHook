package web

import (
	"html"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// wsShareTypeLabel 返回文件类型的中文描述。
func wsShareTypeLabel(t string) string {
	switch t {
	case "image":
		return "图片"
	case "video":
		return "视频"
	case "audio":
		return "音频"
	case "pdf":
		return "PDF"
	case "text":
		return "文本"
	case "archive":
		return "压缩包"
	default:
		return "文件"
	}
}

// wsShareThumbClass 映射文件类型到缩略图配色。
func wsShareThumbClass(t string) string {
	switch t {
	case "image", "video", "audio", "pdf":
		return t
	case "text":
		return "code"
	case "archive":
		return "zip"
	default:
		return "other"
	}
}

// wsShareDirNode 分享目录树节点，用于在分享页展示可进入的文件夹卡片。
type wsShareDirNode struct {
	Path   string
	Name   string
	Parent string
	Files  int
	Size   int64
	MTime  time.Time
}

// wsRenderShareTiles 渲染一层目录（或一组搜索结果）的卡片与底部缩略条。
func wsRenderShareTiles(site WebSite, run *webShareRuntime, files []webShareFile, dirs []wsShareDirNode) (string, string) {
	noDL := site.Share.DisableDownload
	showCount := site.Share.ShowDownloads

	run.mu.Lock()
	statCopy := make(map[string]*webShareStat, len(run.perFile))
	for k, v := range run.perFile {
		c := *v
		statCopy[k] = &c
	}
	run.mu.Unlock()

	var cards strings.Builder
	var films strings.Builder
	// 域名（路径）模式下分享页挂在 /s/{slug} 前缀后，站内地址必须带上该前缀。
	base := wsShareBase(site)
	folderIcon := `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 5a2 2 0 0 1 2-2h5l2 2h5a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/></svg>`
	for _, d := range dirs {
		cards.WriteString(`<div class="file-card folder-card" role="button" tabindex="0" data-type="folder" data-open="0" data-render="0"`)
		cards.WriteString(` data-name="` + html.EscapeString(d.Name) + `" data-dir="` + html.EscapeString(d.Path) + `" data-parent="` + html.EscapeString(d.Parent) + `"`)
		cards.WriteString(` data-size="` + wsFmtSize(d.Size) + `" data-size-bytes="` + strconv.FormatInt(d.Size, 10) + `"`)
		cards.WriteString(` data-mtime="` + strconv.FormatInt(d.MTime.Unix(), 10) + `" data-date="` + d.MTime.Format("2006-01-02 15:04") + `" data-downloads="0" data-kind="文件夹">`)
		cards.WriteString(`<div class="file-thumb thumb-folder"><div class="thumb-ico">` + folderIcon + `</div><span class="kind">DIR</span></div>`)
		cards.WriteString(`<div class="file-body"><div class="file-name">` + html.EscapeString(d.Name) + `</div>`)
		cards.WriteString(`<div class="file-meta"><span>` + strconv.Itoa(d.Files) + ` 个文件</span><span>·</span><span>` + wsFmtSize(d.Size) + `</span></div></div></div>`)
	}
	for i, f := range files {
		mtime := f.MTime
		ext := strings.ToUpper(strings.TrimPrefix(filepath.Ext(f.Name), "."))
		if ext == "" {
			ext = "FILE"
		}
		dlCount := int64(0)
		if st := statCopy[f.Rel]; st != nil {
			dlCount = st.Downloads
		}
		countBadge := ""
		if showCount {
			countBadge = `<span class="count">` + strconv.FormatInt(dlCount, 10) + `</span>`
		}
		rawURL := base + "/raw?path=" + url.QueryEscape(f.Rel)
		dlURL := base + "/dl?path=" + url.QueryEscape(f.Rel)
		thumbInner := `<div class="thumb-ico">` + wsFileIcon(f.Type) + `</div>`
		switch f.Type {
		case "image":
			// 真实缩略图按需加载，加载失败时回退到渐变占位。
			// 禁止下载时先写 data-src，等页面上报在场凭证后再加载，避免首屏请求被 403。
			if site.Share.Preview {
				srcAttr := "src"
				if noDL {
					srcAttr = "data-src"
				}
				thumbInner = `<div class="art"></div><img class="thumb-img" ` + srcAttr + `="` + html.EscapeString(rawURL) + `" alt="" loading="lazy" decoding="async" onerror="this.remove()">`
			}
		case "video":
			thumbInner = `<div class="play-badge"><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg></div>`
		case "audio":
			thumbInner = `<div class="waveform"><i style="height:10px"></i><i style="height:22px"></i><i style="height:30px"></i><i style="height:16px"></i><i style="height:26px"></i><i style="height:38px"></i><i style="height:20px"></i><i style="height:28px"></i><i style="height:12px"></i></div>`
		}
		canRender := site.Share.Preview && wsSharePreviewable(f.Rel)
		cards.WriteString(`<div class="file-card" role="button" tabindex="0" data-type="` + f.Type + `"`)
		fdir := ""
		if idx := strings.LastIndex(f.Rel, "/"); idx >= 0 {
			fdir = f.Rel[:idx]
		}
		cards.WriteString(` data-dir="` + html.EscapeString(fdir) + `" data-name="` + html.EscapeString(f.Name) + `" data-path="` + html.EscapeString(f.Rel) + `" data-size="` + wsFmtSize(f.Size) + `"`)
		cards.WriteString(` data-size-bytes="` + strconv.FormatInt(f.Size, 10) + `" data-mtime="` + strconv.FormatInt(mtime.Unix(), 10) + `"`)
		cards.WriteString(` data-date="` + mtime.Format("2006-01-02 15:04") + `" data-downloads="` + strconv.FormatInt(dlCount, 10) + `"`)
		cards.WriteString(` data-kind="` + wsShareTypeLabel(f.Type) + `" data-raw="` + html.EscapeString(rawURL) + `" data-dl="` + html.EscapeString(dlURL) + `"`)
		cards.WriteString(` data-open="` + boolFlag(site.Share.Preview || !noDL) + `" data-render="` + boolFlag(canRender) + `">`)
		cards.WriteString(`<div class="file-thumb thumb-` + wsShareThumbClass(f.Type) + `">` + thumbInner + `<span class="kind">` + html.EscapeString(ext) + `</span>` + countBadge + `</div>`)
		cards.WriteString(`<div class="file-body"><div class="file-name">` + html.EscapeString(f.Name) + `</div>`)
		cards.WriteString(`<div class="file-meta"><span>` + wsFmtSize(f.Size) + `</span><span>·</span><span>` + mtime.Format("01-02 15:04") + `</span></div></div></div>`)

		if canRender {
			label := strings.TrimSuffix(f.Name, filepath.Ext(f.Name))
			if len([]rune(label)) > 8 {
				label = string([]rune(label)[:8])
			}
			filmClass := "film thumb-" + wsShareThumbClass(f.Type)
			filmInner := `<span class="film-kind">` + html.EscapeString(ext) + `</span>`
			if f.Type == "image" {
				srcAttr := "src"
				if noDL {
					srcAttr = "data-src"
				}
				filmClass += " has-img"
				filmInner = `<img class="film-img thumb-img" ` + srcAttr + `="` + html.EscapeString(rawURL) + `" alt="" loading="lazy" decoding="async" onerror="this.remove()">`
			}
			films.WriteString(`<button type="button" class="` + filmClass + `" data-idx="` + strconv.Itoa(i) + `">` + filmInner + `<span class="film-name">` + html.EscapeString(label) + `</span></button>`)
		}
	}
	return cards.String(), films.String()
}

// wsRenderSharePage 输出文件分享访客页。
func wsRenderSharePage(w http.ResponseWriter, r *http.Request, site WebSite, run *webShareRuntime, idx *webShareIndex) {
	title := site.Name
	desc := site.Share.Description
	noDL := site.Share.DisableDownload
	showCount := site.Share.ShowDownloads

	run.mu.Lock()
	if r.Method == http.MethodGet {
		run.views++
	}
	totalViews := run.views
	totalDL := run.downloads
	run.mu.Unlock()

	subs := idx.Subs[""]
	dirs := make([]wsShareDirNode, 0, len(subs))
	for _, p := range subs {
		if n := idx.Dirs[p]; n != nil {
			dirs = append(dirs, *n)
		}
	}
	cards, films := wsRenderShareTiles(site, run, idx.Files[""], dirs)
	totalSize := idx.Size
	fileCount := idx.Total
	latest := ""
	if !idx.Latest.IsZero() {
		latest = idx.Latest.Format("01-02 15:04")
	}

	codeBadge := ""
	if strings.TrimSpace(site.Share.AccessCode) != "" {
		codeBadge = `<span class="badge b-violet">提取码保护</span>`
	}
	expireBadge := ""
	if strings.TrimSpace(site.Share.ExpiresAt) != "" {
		expireBadge = `<span class="badge b-yellow">` + html.EscapeString(site.Share.ExpiresAt) + ` 到期</span>`
	}
	noDLBadge := ""
	if noDL {
		if site.Share.Preview {
			noDLBadge = `<span class="badge b-slate">仅可在线查看</span>`
		} else {
			noDLBadge = `<span class="badge b-slate">仅可浏览列表</span>`
		}
	}
	pkgBtn := ""
	if site.Share.PackageDownload && !noDL {
		pkgBtn = `<a class="btn" href="` + wsShareBase(site) + `/pkg"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 5a2 2 0 0 1 2-2h5l2 2h5a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/></svg>打包下载</a>`
	}
	bodyClass := ""
	if noDL {
		bodyClass = "no-dl"
	}
	if !showCount {
		if bodyClass != "" {
			bodyClass += " "
		}
		bodyClass += "no-count"
	}

	page := `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + html.EscapeString(title) + `</title><script>
(function(){try{var m=localStorage.getItem('tunhook_share_theme')||'system';var d=m==='dark'||(m==='system'&&window.matchMedia&&matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.setAttribute('data-theme',d?'dark':'light');}catch(e){document.documentElement.setAttribute('data-theme','dark');}})();
</script><style>
:root{color-scheme:dark;--bg:#050b11;--bg-top:#061018;--bg-bottom:#04090e;--bg2:#07131c;--bg3:#0a1822;--bg4:#0c1e29;--bd:rgba(154,196,208,.13);--bd-strong:rgba(154,196,208,.26);--sep:rgba(154,196,208,.1);--accent:#5fe3c0;--accent-rgb:95,227,192;--accent2:#7cc7ff;--warm:#f0b98a;--violet:#b7a4ff;--red:#ff8e8e;--text:#e9f2f4;--text2:#a9bec6;--text3:#6f8892;--font:"MiSans","HarmonyOS Sans SC","Source Han Sans SC","Noto Sans SC","PingFang SC","Microsoft YaHei",sans-serif;--display:"Noto Serif SC","Source Han Serif SC","Songti SC","STSong",Georgia,serif;--mono:"Cascadia Code","JetBrains Mono","SFMono-Regular",Consolas,monospace;--overlay:rgba(3,7,11,.78);--top-bg:rgba(5,11,17,.74);--glass-rgb:12,28,38;--gp:0;--card-bg:linear-gradient(180deg,rgba(12,27,38,.8),rgba(8,18,26,.92));--card-shadow:0 1px 2px rgba(0,0,0,.25);--card-hover-shadow:0 20px 46px rgba(0,0,0,.46);--preview-shadow:0 50px 140px rgba(0,0,0,.68);--viewer-bg:#03080c;--code-bg:#061018;--code-text:#c7d9e2;--glow-a:rgba(95,227,192,.15);--glow-b:rgba(124,199,255,.11);--dot:rgba(160,210,220,.1);--noise:.032;--scroll-thumb:rgba(154,196,208,.22);--scroll-thumb-hover:rgba(95,227,192,.4);--tok-com:#5b7187;--tok-str:#a8d97a;--tok-num:#e8b06a;--tok-kw:#c792ea;--tok-fn:#5fe3c0;--tok-tag:#7fb0ff;--tok-attr:#b7a4ff;--minimap-bg:rgba(255,255,255,.02);--minimap-border:rgba(255,255,255,.06)}
html[data-theme="light"]{color-scheme:light;--bg:#f2f6f4;--bg-top:#f8fbfa;--bg-bottom:#eef3f1;--bg2:#ffffff;--bg3:#f7fbf9;--bg4:#eaf1ef;--bd:#d9e4e0;--bd-strong:#c2d2cd;--sep:#e4ece9;--accent:#0d8a72;--accent-rgb:13,138,114;--accent2:#2e9fc4;--warm:#b4763a;--violet:#6f52c9;--red:#b33a3a;--text:#14201d;--text2:#4f635d;--text3:#7b8f89;--overlay:rgba(8,18,15,.55);--top-bg:rgba(242,246,244,.86);--glass-rgb:255,255,255;--card-bg:linear-gradient(180deg,#ffffff,#f8fbfa);--card-shadow:0 1px 2px rgba(16,32,28,.06);--card-hover-shadow:0 18px 40px rgba(16,32,28,.14);--preview-shadow:0 40px 100px rgba(16,32,28,.2);--viewer-bg:#eef3f1;--code-bg:#ffffff;--code-text:#243447;--glow-a:rgba(13,138,114,.1);--glow-b:rgba(46,159,196,.08);--dot:rgba(60,110,100,.12);--noise:.02;--scroll-thumb:rgba(90,115,105,.25);--scroll-thumb-hover:rgba(13,138,114,.4);--tok-com:#7a8b9c;--tok-str:#22863a;--tok-num:#b45309;--tok-kw:#6f42c1;--tok-fn:#0d8a72;--tok-tag:#005cc5;--tok-attr:#8250df;--minimap-bg:rgba(16,32,28,.02);--minimap-border:#e4ece9}
html[data-theme="light"] .b-violet{color:#6f42c1;border-color:rgba(111,66,193,.25);background:rgba(111,66,193,.07)}
html[data-theme="light"] .b-yellow{color:#b45309;border-color:rgba(180,83,9,.25);background:rgba(180,83,9,.08)}
*{box-sizing:border-box;scrollbar-width:thin;scrollbar-color:var(--scroll-thumb) transparent}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--scroll-thumb);border:2px solid transparent;background-clip:content-box;border-radius:99px}
::-webkit-scrollbar-thumb:hover{background:var(--scroll-thumb-hover);border:2px solid transparent;background-clip:content-box;border-radius:99px}
::-webkit-scrollbar-corner{background:transparent}
html,body{min-height:100%}
body{margin:0;min-height:100vh;color:var(--text);font-family:var(--font);font-size:14px;line-height:1.5;background:radial-gradient(1100px 620px at 10% -12%,var(--glow-a),transparent 62%),radial-gradient(900px 560px at 94% -8%,var(--glow-b),transparent 58%),linear-gradient(180deg,var(--bg-top) 0%,var(--bg) 44%,var(--bg-bottom) 100%);-webkit-font-smoothing:antialiased;transition:background-color .2s,color .2s}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;background-image:radial-gradient(var(--dot) 1px,transparent 1px);background-size:26px 26px;-webkit-mask-image:linear-gradient(180deg,rgba(0,0,0,.9),transparent 72%);mask-image:linear-gradient(180deg,rgba(0,0,0,.9),transparent 72%)}
body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;opacity:var(--noise);background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='180' height='180'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='2'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")}
a{color:var(--accent);text-decoration:none}
button{font-family:inherit;font-size:inherit;color:inherit;cursor:pointer}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.badge{display:inline-flex;align-items:center;gap:4px;font:9.5px var(--mono);letter-spacing:.05em;border-radius:5px;padding:4px 8px;border:1px solid var(--bd);background:rgba(10,24,34,.62);color:var(--text3);white-space:nowrap}
html[data-theme="light"] .badge{background:rgba(255,255,255,.7)}
.b-violet{color:var(--violet);border-color:rgba(183,164,255,.3);background:rgba(183,164,255,.07)}
.b-yellow{color:var(--warm);border-color:rgba(240,185,138,.28);background:rgba(240,185,138,.06)}
.b-slate{color:var(--text3)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;height:34px;padding:0 13px;border:1px solid var(--bd-strong);border-radius:8px;background:rgba(12,26,37,.7);color:var(--text2);font-size:11.5px;font-weight:500;transition:border-color .18s,background .18s,color .18s,transform .18s}
html[data-theme="light"] .btn:not(.primary){background:rgba(255,255,255,.8)}
.btn:hover{border-color:rgba(var(--accent-rgb),.45);color:var(--text);background:rgba(var(--accent-rgb),.06)}
.btn:active{transform:translateY(1px)}
.btn.primary{border:none;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#04151b;font-weight:700;box-shadow:0 10px 26px rgba(var(--accent-rgb),.2)}
.btn.primary:hover{filter:brightness(1.06);color:#04151b}
.theme-toggle{width:34px;height:34px;flex:none;border:1px solid var(--bd);border-radius:8px;background:rgba(10,24,34,.6);color:var(--text3);display:inline-flex;align-items:center;justify-content:center;padding:0;transition:border-color .18s,color .18s,background .18s}
html[data-theme="light"] .theme-toggle{background:rgba(255,255,255,.75)}
.theme-toggle:hover{border-color:rgba(var(--accent-rgb),.4);color:var(--accent)}
.share-top{position:sticky;top:0;z-index:80;background:var(--top-bg);backdrop-filter:blur(18px) saturate(140%);-webkit-backdrop-filter:blur(18px) saturate(140%);border-bottom:1px solid transparent;transition:border-color .2s,box-shadow .2s}
.share-top.stuck{border-bottom-color:var(--bd);box-shadow:0 18px 50px rgba(0,0,0,.28)}
.share-head{max-width:1240px;margin:0 auto;padding:20px 32px;display:flex;align-items:center;gap:18px;transition:padding .2s}
.share-top.stuck .share-head{padding:12px 32px}
.share-brand{display:flex;align-items:center;gap:11px;flex:none;margin:0}
.share-brand .mark{width:36px;height:36px;border-radius:11px;display:flex;align-items:center;justify-content:center;background:linear-gradient(140deg,var(--accent),var(--accent2));color:#04151b;font-weight:800;font-size:15px;box-shadow:0 0 0 1px rgba(255,255,255,.14) inset,0 12px 32px rgba(var(--accent-rgb),.22);transition:width .2s,height .2s,font-size .2s,border-radius .2s}
.share-top.stuck .share-brand .mark{width:30px;height:30px;border-radius:9px;font-size:13px}
.brand-copy b{display:block;font-size:13px;font-weight:650;letter-spacing:.01em}
.brand-copy span{display:block;font:10px var(--mono);color:var(--text3);letter-spacing:.04em;margin-top:2px}
.share-top.stuck .brand-copy span{display:none}
.top-actions{margin-left:auto;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.wrap{position:relative;z-index:1;max-width:1240px;margin:0 auto;padding:0 32px 56px}
.share-hero{position:relative;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:48px;align-items:end;padding:52px 0 34px}
.hero-copy .eyebrow{display:flex;align-items:center;gap:9px;font:10px var(--mono);letter-spacing:.2em;color:var(--accent);text-transform:uppercase}
.hero-copy .eyebrow i{display:block;width:26px;height:1px;background:linear-gradient(90deg,var(--accent),transparent)}
.hero-copy h1{font-family:var(--display);font-size:clamp(38px,5.4vw,64px);font-weight:600;line-height:1.04;letter-spacing:-.025em;margin:16px 0 14px}
.hero-badges{position:absolute;top:18px;right:0;z-index:2;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.hero-copy p{max-width:620px;margin:0;color:var(--text2);font-size:12.5px;line-height:1.85}
.stats{display:flex;align-items:flex-end;margin:0}
.stats>div{padding:0 20px;border-left:1px solid var(--bd);min-width:96px}
.stats>div:first-child{border-left:0;padding-left:0}
.stats b{display:block;font-family:var(--display);font-size:30px;font-weight:600;line-height:1.1;letter-spacing:-.02em}
.stats span{display:block;margin-top:5px;font:9.5px var(--mono);letter-spacing:.1em;color:var(--text3)}
.share-toolbar{position:sticky;top:0;z-index:60;display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding:14px 0}
.tb-glass{position:fixed;top:0;left:0;right:0;height:var(--tbh,0);z-index:-1;pointer-events:none;opacity:var(--gp);background:linear-gradient(180deg,rgba(var(--glass-rgb),.58),rgba(var(--glass-rgb),.34));backdrop-filter:blur(24px) saturate(150%);-webkit-backdrop-filter:blur(24px) saturate(150%);box-shadow:inset 0 1px 0 rgba(255,255,255,.12),inset 0 -1px 0 rgba(255,255,255,.06),0 12px 30px rgba(0,0,0,.2)}
.crumb-path{display:flex;align-items:center;gap:3px;min-width:0;overflow:hidden}
.crumb{border:none;background:none;padding:3px 6px;border-radius:5px;color:var(--text3);font:11px var(--mono);white-space:nowrap;max-width:240px;overflow:hidden;text-overflow:ellipsis}
.crumb:hover{background:rgba(var(--accent-rgb),.06);color:var(--text2)}
.crumb.active{color:var(--text2);font-weight:600}
.crumb-sep{color:var(--text3);opacity:.45;font-size:10px}
.search{position:relative;margin-left:auto;width:250px}
.search svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--text3);pointer-events:none}
.search input{width:100%;height:34px;border:1px solid var(--bd-strong);border-radius:8px;background:rgba(6,16,23,.85);color:var(--text);font-size:11.5px;padding:0 12px 0 32px;outline:none;transition:border-color .18s,box-shadow .18s}
html[data-theme="light"] .search input{background:rgba(255,255,255,.85)}
.search input::placeholder{color:var(--text3)}
.search input:focus{border-color:rgba(var(--accent-rgb),.55);box-shadow:0 0 0 3px rgba(var(--accent-rgb),.1)}
.db-select{height:34px;border:1px solid var(--bd-strong);border-radius:8px;background-color:rgba(6,16,23,.85);color:var(--text2);font-size:11.5px;padding:0 28px 0 10px;outline:none;cursor:pointer;color-scheme:dark;-webkit-appearance:none;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%236f8892' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 9px center}
html[data-theme="light"] .db-select{background-color:rgba(255,255,255,.85);color-scheme:light;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%237b8f89' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E")}
.db-select:focus{border-color:var(--accent)}
.db-select option{background:var(--bg2);color:var(--text)}
.view-toggle{display:flex;padding:2px;border:1px solid var(--bd);border-radius:8px;background:rgba(6,16,23,.7)}
html[data-theme="light"] .view-toggle{background:rgba(255,255,255,.7)}
.view-toggle button{border:none;background:none;width:30px;height:28px;border-radius:6px;color:var(--text3);display:flex;align-items:center;justify-content:center;transition:background .15s,color .15s}
.view-toggle button:hover{color:var(--text2)}
.view-toggle button.active{background:rgba(var(--accent-rgb),.12);color:var(--accent)}
.file-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:18px;padding:26px 0 30px}
.file-card{border:1px solid var(--bd);border-radius:14px;background:var(--card-bg);overflow:hidden;text-align:left;padding:0;transition:transform .22s cubic-bezier(.2,.7,.3,1),border-color .22s,box-shadow .22s;box-shadow:var(--card-shadow);cursor:pointer;animation:rise .45s both}
.file-card:hover{transform:translateY(-4px);border-color:rgba(var(--accent-rgb),.34);box-shadow:var(--card-hover-shadow)}
.file-card:focus-visible{border-color:var(--accent)}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.file-grid.no-anim .file-card{animation:none}
.file-thumb{position:relative;aspect-ratio:4/3;height:auto;overflow:hidden;display:flex;align-items:center;justify-content:center;color:rgba(255,255,255,.72)}
.file-thumb::after{content:"";position:absolute;inset:0;background:linear-gradient(180deg,transparent 48%,rgba(4,10,15,.5));pointer-events:none;z-index:1}
.file-thumb .kind{position:absolute;left:11px;top:11px;z-index:2;font:9px var(--mono);font-weight:600;letter-spacing:.12em;color:rgba(255,255,255,.86);background:rgba(4,10,15,.56);border:1px solid rgba(255,255,255,.16);border-radius:5px;padding:4px 7px;backdrop-filter:blur(8px)}
.file-thumb .count{position:absolute;right:11px;bottom:11px;z-index:2;display:flex;align-items:center;gap:4px;font:9.5px var(--mono);color:rgba(255,255,255,.8);background:rgba(4,10,15,.5);border:1px solid rgba(255,255,255,.12);border-radius:5px;padding:3px 6px}
.thumb-img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;display:block;background:transparent;transition:transform .6s cubic-bezier(.2,.7,.3,1)}
.file-card:hover .thumb-img{transform:scale(1.06)}
.file-thumb svg{width:34px;height:34px}
.thumb-ico{position:relative;z-index:1;display:flex;align-items:center;justify-content:center;width:100%;height:100%}
.thumb-image{background:radial-gradient(220px 160px at 70% 30%,rgba(95,227,192,.2),transparent 70%),linear-gradient(145deg,#0c2833,#164b58 55%,#0a1720)}
.thumb-image .art{position:absolute;inset:0;background:radial-gradient(150px 110px at 26% 28%,rgba(255,208,150,.35),transparent 70%),linear-gradient(180deg,transparent 40%,rgba(7,20,26,.5))}
.thumb-video{background:radial-gradient(240px 180px at 60% 40%,rgba(124,199,255,.22),transparent 70%),linear-gradient(145deg,#0a1e2b,#123746 55%,#07151d)}
.thumb-pdf{background:radial-gradient(220px 160px at 70% 20%,rgba(240,185,138,.16),transparent 70%),linear-gradient(145deg,#2a1712,#4a261c 58%,#1a0e0b)}
.thumb-audio{background:radial-gradient(220px 160px at 30% 20%,rgba(95,227,192,.2),transparent 70%),linear-gradient(145deg,#082523,#0c3b38 58%,#07191a)}
.thumb-code{background:radial-gradient(220px 160px at 30% 20%,rgba(124,199,255,.18),transparent 70%),linear-gradient(145deg,#0a1728,#12253c 58%,#08111c)}
.thumb-zip{background:radial-gradient(220px 160px at 65% 25%,rgba(240,185,138,.18),transparent 70%),linear-gradient(145deg,#2b2415,#4a3b1e 58%,#1a140a)}
.thumb-folder{background:radial-gradient(240px 170px at 70% 20%,rgba(240,185,138,.18),transparent 70%),linear-gradient(145deg,#2b2415,#4a3a20 58%,#1a140b)}
.thumb-other{background:linear-gradient(145deg,#15232e,#223442 58%,#0d171f)}
.play-badge{position:relative;z-index:2;width:44px;height:44px;border-radius:50%;background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.36);display:flex;align-items:center;justify-content:center;color:#fff;backdrop-filter:blur(6px)}
.waveform{position:relative;z-index:2;display:flex;align-items:center;gap:3px;height:40px}
.waveform i{display:block;width:3px;border-radius:2px;background:rgba(210,255,246,.62)}
.file-body{padding:13px 14px 15px}
.file-name{font-size:12.5px;font-weight:600;line-height:1.5;word-break:break-all;color:var(--text);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;min-height:19px}
.file-meta{display:flex;align-items:center;gap:7px;margin-top:6px;font:10px var(--mono);color:var(--text3)}
.file-meta span:nth-child(2){opacity:.55}
.file-grid.list{display:flex;flex-direction:column;gap:10px}
.file-grid.list .file-card{display:flex;align-items:stretch;animation:none}
.file-grid.list .file-thumb{width:150px;height:112px;aspect-ratio:auto;flex:none}
.file-grid.list .file-body{flex:1;display:flex;align-items:center;gap:18px;padding:12px 16px;min-width:0}
.file-grid.list .file-name{flex:1;min-width:0;-webkit-line-clamp:1;min-height:0}
.file-grid.list .file-meta{margin:0;flex:none}
.empty-tip{grid-column:1/-1;padding:70px 0;text-align:center;color:var(--text3);font-size:12px}
.share-foot{position:relative;border-top:1px solid var(--bd);padding:18px 0 0;color:var(--text3);font-size:10.5px}
.share-foot-in{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;max-width:none;padding:0}
.share-foot .owner{display:flex;align-items:center;gap:8px}
.avatar{width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#04151b;font-size:9px;font-weight:800}
.overlay{position:fixed;inset:0;z-index:100;display:none;align-items:center;justify-content:center;padding:28px;background:var(--overlay);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}
.overlay.open{display:flex}
.preview{width:min(1180px,100%);height:min(760px,100%);display:flex;flex-direction:column;background:linear-gradient(180deg,#0b1a24,#08131b);border:1px solid var(--bd-strong);border-radius:18px;overflow:hidden;box-shadow:var(--preview-shadow);animation:pop .26s cubic-bezier(.2,.8,.2,1)}
html[data-theme="light"] .preview{background:linear-gradient(180deg,#ffffff,#f7fbf9)}
@keyframes pop{from{opacity:0;transform:translateY(14px) scale(.985)}to{opacity:1;transform:none}}
.preview-head{height:62px;flex:none;display:flex;align-items:center;gap:12px;padding:0 16px 0 18px;border-bottom:1px solid var(--bd);background:rgba(9,20,28,.6)}
html[data-theme="light"] .preview-head{background:rgba(255,255,255,.6)}
.pv-ico{width:32px;height:32px;flex:none;border-radius:8px;display:flex;align-items:center;justify-content:center;border:1px solid var(--bd);background:rgba(var(--accent-rgb),.06);color:var(--accent)}
.pv-name{min-width:0}
.pv-name b{display:block;font-size:12.5px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pv-name span{display:block;font:9.5px var(--mono);color:var(--text3);margin-top:2px}
.preview-head .close{margin-left:auto;width:30px;height:30px;flex:none;border:1px solid transparent;background:none;color:var(--text3);border-radius:7px;display:inline-flex;align-items:center;justify-content:center;padding:0}
.preview-head .close:hover{background:var(--bg4);color:var(--text)}
.pv-dl-top{display:none;width:30px;height:30px;border:1px solid var(--bd);border-radius:7px;color:var(--text2);align-items:center;justify-content:center;flex:none}
.pv-dl-top:hover{border-color:rgba(var(--accent-rgb),.5);color:var(--accent)}
.no-dl .pv-dl-top{display:none!important}
.preview-body{flex:1;display:flex;min-height:0}
.viewer{flex:1;position:relative;background:var(--viewer-bg);display:flex;align-items:center;justify-content:center;overflow:hidden}
.viewer::before{content:"";position:absolute;inset:0;background-image:linear-gradient(rgba(154,196,208,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(154,196,208,.045) 1px,transparent 1px);background-size:44px 44px;-webkit-mask-image:radial-gradient(circle at 50% 50%,#000,transparent 78%);mask-image:radial-gradient(circle at 50% 50%,#000,transparent 78%);pointer-events:none}
html[data-theme="light"] .viewer::before{background-image:linear-gradient(rgba(60,110,100,.07) 1px,transparent 1px),linear-gradient(90deg,rgba(60,110,100,.07) 1px,transparent 1px)}
#pvBody{position:relative;z-index:2;width:100%;height:100%;display:flex;align-items:center;justify-content:center;padding:26px}
#pvBody img,#pvBody video{max-width:100%;max-height:100%;border-radius:10px;box-shadow:0 26px 70px rgba(0,0,0,.5)}
#pvBody audio{width:min(460px,90%)}
#pvBody iframe{width:100%;height:100%;border:none;background:#fff;border-radius:10px}
#pvBody .code-wrap{width:100%;height:100%;display:flex;min-width:0;position:relative;border-radius:10px;overflow:hidden;border:1px solid var(--bd)}
#pvBody .code-wrap pre{flex:1;min-width:0;height:100%;margin:0;overflow:auto;padding:22px 26px;background:var(--code-bg);color:var(--code-text);font-family:var(--mono);font-size:12px;line-height:1.9;white-space:pre-wrap;word-break:break-all;scrollbar-width:thin;scrollbar-color:var(--scroll-thumb) transparent}
#pvBody .code-wrap pre::-webkit-scrollbar{width:8px;height:8px}
#pvBody .code-wrap pre::-webkit-scrollbar-thumb{background:var(--scroll-thumb);border:2px solid transparent;background-clip:content-box;border-radius:99px}
#pvBody .code-wrap pre::-webkit-scrollbar-thumb:hover{background:var(--scroll-thumb-hover);border:2px solid transparent;background-clip:content-box;border-radius:99px}
#pvBody .code-wrap pre .tok-com{color:var(--tok-com);font-style:italic}
#pvBody .code-wrap pre .tok-str{color:var(--tok-str)}
#pvBody .code-wrap pre .tok-num{color:var(--tok-num)}
#pvBody .code-wrap pre .tok-kw{color:var(--tok-kw)}
#pvBody .code-wrap pre .tok-fn{color:var(--tok-fn)}
#pvBody .code-wrap pre .tok-tag{color:var(--tok-tag)}
#pvBody .code-wrap pre .tok-attr{color:var(--tok-attr)}
.code-minimap{position:relative;flex:none;width:78px;height:100%;padding:16px 9px 16px 0;cursor:pointer;touch-action:none;user-select:none;border-left:1px solid var(--minimap-border);background:var(--minimap-bg)}
.code-minimap canvas{display:block;width:100%;height:100%;opacity:.9}
.code-minimap:hover canvas{opacity:1}
.mm-view{position:absolute;left:4px;right:5px;border-radius:4px;background:rgba(var(--accent-rgb),.13);border:1px solid rgba(var(--accent-rgb),.32);pointer-events:none}
.pv-art{width:min(520px,72%);aspect-ratio:4/3;border-radius:16px;background:radial-gradient(180px 120px at 25% 25%,rgba(255,255,255,.28),transparent 70%),radial-gradient(220px 160px at 72% 72%,rgba(95,227,192,.35),transparent 70%),linear-gradient(135deg,#155d70,#2e9fc4);box-shadow:0 30px 80px rgba(0,0,0,.45);position:relative;overflow:hidden}
.img-wrap{width:100%;height:100%;display:flex;align-items:center;justify-content:center;position:relative}
.img-shield{display:none}
.no-dl .img-shield{display:block;position:absolute;inset:0;z-index:2}
.pv-none{position:relative;z-index:2;width:100%;height:100%;display:flex;flex-direction:column;gap:14px;align-items:center;justify-content:center;color:var(--text3);text-align:center}
.pv-none .big-ico{width:64px;height:64px;border-radius:16px;background:var(--bg4);border:1px solid var(--bd);display:flex;align-items:center;justify-content:center;color:var(--text3)}
.pv-guard{position:relative;z-index:2;display:flex;flex-direction:column;align-items:center;gap:12px;max-width:430px;padding:34px 30px;border:1px solid rgba(255,142,142,.2);border-radius:14px;background:rgba(26,12,16,.5);text-align:center}
html[data-theme="light"] .pv-guard{background:rgba(255,245,244,.8);border-color:rgba(179,58,58,.18)}
.pv-guard .guard-ico{width:54px;height:54px;border-radius:15px;display:flex;align-items:center;justify-content:center;border:1px solid rgba(255,142,142,.3);background:rgba(255,142,142,.08);color:var(--red)}
.pv-guard b{font-size:14px;font-weight:650}
.pv-guard p{margin:0;max-width:330px;color:var(--text2);font-size:11.5px;line-height:1.85}
.pv-guard span{font:9.5px var(--mono);letter-spacing:.04em;color:var(--text3)}
.pv-wm{position:absolute;inset:0;z-index:3;pointer-events:none;overflow:hidden;display:none}
.pv-wm.on{display:block}
.pv-wm .wm-diamonds{position:absolute;left:-50%;top:-50%;width:200%;height:200%;display:grid;grid-template-columns:repeat(auto-fill,minmax(168px,1fr));grid-auto-rows:168px;place-items:center}
.pv-wm .wm-dia{position:relative;width:118px;height:118px;transform:rotate(45deg);border:1px solid rgba(160,50,45,.4);display:flex;align-items:center;justify-content:center}
.pv-wm .wm-dia::before{content:"";position:absolute;inset:8px;border:1px solid rgba(160,50,45,.2)}
.pv-wm .wm-dia b{transform:rotate(-45deg);font:8.5px/1.7 var(--mono);font-weight:400;color:rgba(125,35,32,.52);text-align:center;max-width:78px}
.preview-info{width:300px;flex:none;border-left:1px solid var(--bd);padding:18px;overflow-y:auto;background:linear-gradient(180deg,rgba(11,27,38,.5),rgba(7,16,23,.86))}
html[data-theme="light"] .preview-info{background:linear-gradient(180deg,rgba(255,255,255,.6),rgba(247,251,249,.95))}
.info-title{font:10px var(--mono);letter-spacing:.16em;color:var(--text3);margin:0 0 10px}
.info-row{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:8px 0;border-bottom:1px solid rgba(154,196,208,.09);font-size:11px}
.info-row:last-of-type{border-bottom:0}
.info-row span{color:var(--text3);flex:none}
.info-row b{font-weight:600;color:var(--text2);text-align:right;word-break:break-all}
.info-actions{display:flex;flex-direction:column;gap:7px;margin-top:16px}
.info-actions .btn{width:100%}
.filmstrip{height:82px;flex:none;border-top:1px solid var(--bd);display:flex;align-items:center;gap:8px;padding:0 16px;overflow-x:auto;overflow-y:hidden;background:rgba(8,18,26,.7);scrollbar-width:none}
html[data-theme="light"] .filmstrip{background:rgba(247,251,249,.9)}
.filmstrip::-webkit-scrollbar{display:none}
.film{position:relative;width:54px;height:54px;flex:none;border:2px solid transparent;border-radius:8px;padding:0;overflow:hidden;background:var(--bg4);display:flex;align-items:center;justify-content:center;color:var(--text3)}
.film.active{border-color:var(--accent);box-shadow:0 0 0 3px rgba(var(--accent-rgb),.12)}
.film-img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.film-kind{font-size:8px;font-weight:700;color:#fff}
.film-name{position:absolute;left:0;right:0;bottom:0;background:rgba(3,8,12,.7);color:#fff;font-size:7.5px;padding:2px 3px;text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.no-dl .info-actions{display:none!important}
.no-count .info-count,.no-count .file-thumb .count,.no-count .meta-dl,.no-count .stat-dl{display:none!important}
.no-dl{-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none;user-select:none;-webkit-touch-callout:none}
.no-dl img,.no-dl video{-webkit-user-drag:none;user-select:none;-webkit-touch-callout:none}
.no-dl a{-webkit-user-drag:none}
@media(max-width:1100px){.file-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.share-hero{grid-template-columns:1fr;gap:28px}.stats{width:100%}.stats>div{min-width:0;flex:1}}
@media(max-width:900px){.preview-info{display:none}.pv-dl-top{display:inline-flex;margin-left:auto}.preview-head .close{margin-left:6px}#pvBody{padding:18px}}
@media(max-width:640px){.share-head{padding:14px 16px}.share-top.stuck .share-head{padding:10px 16px}.top-actions .badge{display:none}.brand-copy span{display:none}.wrap{padding:0 16px 42px}.share-hero{padding:30px 0 22px;gap:22px}.hero-copy h1{font-size:36px;margin:12px 0 10px}.hero-badges{position:static;width:100%;padding:0;margin:0 0 12px;justify-content:flex-end}.hero-copy p{font-size:12px}.stats{display:grid;grid-template-columns:repeat(2,1fr);gap:16px 0}.stats>div{padding:0 0 0 14px;border-left:0}.stats>div:nth-child(even){border-left:1px solid var(--bd);padding-left:14px}.stats b{font-size:24px}.share-toolbar{gap:10px}.search{width:100%;margin-left:0;order:3}.view-toggle{margin-left:auto}.file-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:11px}.file-body{padding:10px 11px 12px}.file-name{font-size:11.5px}.file-meta{font-size:9px;gap:5px}.file-thumb .kind{left:8px;top:8px;font-size:8px;padding:3px 6px}.file-thumb .count{right:8px;bottom:8px;font-size:8.5px}.file-grid.list .file-thumb{width:96px;height:72px}.file-grid.list .file-body{display:block;padding:10px 12px}.file-grid.list .file-meta{margin-top:5px}.overlay{padding:0}.preview{height:100%;border-radius:0;border:0}.preview-head{height:56px;padding:0 12px}.pv-ico{width:28px;height:28px}.filmstrip{height:70px;padding:0 12px}.film{width:46px;height:46px}#pvBody{padding:14px}#pvBody .code-wrap pre{padding:16px 18px}.code-minimap{display:none}.share-foot{padding:14px 0 0}.share-foot-in{padding:0}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>`
	if noDL {
		// 尽早接管 console：页面后续脚本不会再向开发者工具输出任何内容。
		page += `<script>
(function(){
  var clearFn=null;
  try{
    var noop=function(){};
    var names=['log','info','warn','error','debug','table','dir','trace','group','groupEnd','time','timeEnd','assert','count','profile','profileEnd','clear'];
    var c=window.console||{};
    clearFn=c.clear?c.clear.bind(c):null;
    for(var i=0;i<names.length;i++){try{c[names[i]]=noop;}catch(e){}}
    window.console=c;
  }catch(e){}
  var tick=function(){try{clearFn&&clearFn();}catch(e){}};
  tick();
  setInterval(tick,500);
})();
</script>`
	}
	descHTML := ""
	if desc != "" {
		descHTML = `<p>` + html.EscapeString(desc) + `</p>`
	}
	eyebrowLatest := ""
	if latest != "" {
		eyebrowLatest = ` · 最近更新 ` + html.EscapeString(latest)
	}
	// 标题上方的小字：优先用副标题，未填写时回退到 TunHook。
	eyebrowLabel := strings.TrimSpace(site.Share.Subtitle)
	if eyebrowLabel == "" {
		eyebrowLabel = "TunHook"
	}
	wmJS := "[]"
	if lines := wsWatermarkLines(site, r); len(lines) > 0 {
		var q []string
		for _, l := range lines {
			q = append(q, strconv.Quote(l))
		}
		wmJS = "[" + strings.Join(q, ",") + "]"
	}
	page += `</head><body class="` + bodyClass + `">
<main class="wrap">
<section class="share-hero">
<div class="hero-badges"><button type="button" class="theme-toggle" id="themeBtn" title="主题：跟随系统" aria-label="切换主题"><svg id="themeIcon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg></button>` + noDLBadge + codeBadge + expireBadge + pkgBtn + `</div>
<div class="hero-copy"><div class="eyebrow"><i></i>` + html.EscapeString(eyebrowLabel) + eyebrowLatest + `</div><h1>` + html.EscapeString(title) + `</h1>` + descHTML + `</div>
<div class="stats"><div><b>` + strconv.Itoa(fileCount) + `</b><span>个文件</span></div><div><b>` + wsFmtSize(totalSize) + `</b><span>合计大小</span></div><div><b>` + strconv.FormatInt(totalViews, 10) + `</b><span>查看次数</span></div><div class="stat-dl"><b>` + strconv.FormatInt(totalDL, 10) + `</b><span>下载次数</span></div></div>
</section>
<div class="share-toolbar"><span class="tb-glass" aria-hidden="true"></span><div class="crumb-path" id="crumbs"><button type="button" class="crumb active" data-dir="">全部文件</button></div><div class="search"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg><input id="q" placeholder="搜索文件名" autocomplete="off" /></div><select class="db-select" id="sort"><option value="mtime">按更新时间</option><option value="name">按名称</option><option value="size">按大小</option><option value="downloads">按下载量</option></select><div class="view-toggle"><button type="button" class="active" data-view="grid" title="网格"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg></button><button type="button" data-view="list" title="列表"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg></button></div></div>
<section class="file-grid" id="grid">` + cards + `</section>
<footer class="share-foot"><div class="share-foot-in"><div class="owner"><span class="avatar">T</span><span>由 ` + html.EscapeString(site.Name) + ` 分享 · 通过 TunHook Web 服务发布</span></div><span>分享内容仅供内部使用 · 请勿外传</span></div></footer>
</main>
<div class="overlay" id="pv"><div class="preview">
<div class="preview-head"><span class="pv-ico"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg></span><div class="pv-name"><b id="pvName"></b><span id="pvMeta"></span></div><a class="pv-dl-top" id="pvDlTop" href="#" title="下载" aria-label="下载"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12M7 10l5 5 5-5M4 21h16"/></svg></a><button type="button" class="close" id="pvClose" title="关闭" aria-label="关闭"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 6l12 12M18 6 6 18"/></svg></button></div>
<div class="preview-body"><div class="viewer"><div id="pvBody"></div><div class="pv-wm" id="pvWm"></div></div><aside class="preview-info"><div class="info-title">FILE INFO</div><div class="info-row"><span>大小</span><b id="pvSize"></b></div><div class="info-row"><span>类型</span><b id="pvType"></b></div><div id="pvExtra"></div><div class="info-row"><span>修改时间</span><b id="pvDate"></b></div><div class="info-row info-count"><span>下载次数</span><b id="pvDlCount"></b></div><div class="info-row"><span>分享者</span><b>` + html.EscapeString(site.Name) + `</b></div><div class="info-actions"><a class="btn primary info-dl" id="pvDl" href="#">下载文件</a></div></aside></div>
<div class="filmstrip" id="films">` + films + `</div></div></div>

<script>
(function(){
  window.__tunhookWmLines=` + wmJS + `;
  window.__tunhookBase=` + strconv.Quote(wsShareBase(site)) + `;
  var B=window.__tunhookBase||'';
  var pv=document.getElementById('pv'), body=document.getElementById('pvBody');
  var nameEl=document.getElementById('pvName'), metaEl=document.getElementById('pvMeta');
  var sizeEl=document.getElementById('pvSize'), typeEl=document.getElementById('pvType');
  var dateEl=document.getElementById('pvDate'), dlCountEl=document.getElementById('pvDlCount');
  var extraEl=document.getElementById('pvExtra');
  var dlEl=document.getElementById('pvDl'), films=document.getElementById('films');
  var dlTopEl=document.getElementById('pvDlTop'), wmPv=document.getElementById('pvWm');
  var grid=document.getElementById('grid'), q=document.getElementById('q'), sortSel=document.getElementById('sort');
  var crumbs=document.getElementById('crumbs');
  var tiles=[],cards=[],openable=[];
  var currentDir='', cur=-1, mmCleanup=null, searchLimit=0;
  var infoToken=0, infoRows={};
  var FMT={jpg:'JPEG',jpeg:'JPEG',png:'PNG',gif:'GIF',webp:'WEBP',avif:'AVIF',svg:'SVG',bmp:'BMP',ico:'ICO',mp4:'MP4',webm:'WEBM',mov:'MOV',m4v:'M4V',ogg:'OGG',mp3:'MP3',wav:'WAV',flac:'FLAC',m4a:'M4A',aac:'AAC'};
  var LANG={go:'Go',js:'JavaScript',jsx:'React JSX',ts:'TypeScript',tsx:'TypeScript React',py:'Python',rb:'Ruby',java:'Java',kt:'Kotlin',rs:'Rust',swift:'Swift',c:'C',h:'C 头文件',cpp:'C++',cc:'C++',hpp:'C++ 头文件',cs:'C#',php:'PHP',sh:'Shell',bash:'Shell',zsh:'Shell',ps1:'PowerShell',html:'HTML',htm:'HTML',css:'CSS',scss:'SCSS',less:'LESS',json:'JSON',xml:'XML',yaml:'YAML',yml:'YAML',toml:'TOML',md:'Markdown',markdown:'Markdown',sql:'SQL',lua:'Lua',ini:'配置',conf:'配置',cfg:'配置',log:'日志',txt:'纯文本',csv:'CSV'};
  var CODEC={h264:'H.264',hevc:'H.265/HEVC',vp8:'VP8',vp9:'VP9',av1:'AV1',aac:'AAC',mp3:'MP3',opus:'Opus',vorbis:'Vorbis',flac:'FLAC',pcm_s16le:'PCM',pcm_s24le:'PCM',ac3:'AC-3',eac3:'E-AC-3',alac:'ALAC'};
  function fileExt(name){var p=String(name).split('.');return p.length>1?p.pop().toLowerCase():'';}
  function fmtDur(sec){
    sec=Math.round(sec);
    if(!isFinite(sec)||sec<=0)return'';
    var h=Math.floor(sec/3600),m=Math.floor(sec%3600/60),s=sec%60;
    return (h?h+':':'')+('0'+m).slice(-2)+':'+('0'+s).slice(-2);
  }
  function fmtHz(hz){return hz>=1000?(Math.round(hz/100)/10)+' kHz':hz+' Hz';}
  function infoRow(key,label,val){
    var d=document.createElement('div');d.className='info-row';
    d.innerHTML='<span>'+esc(label)+'</span><b></b>';
    var b=d.querySelector('b');
    if(val) b.textContent=val; else d.style.display='none';
    extraEl.appendChild(d);
    infoRows[key]={row:d,val:b};
  }
  function infoSet(key,val){
    var it=infoRows[key];
    if(!it||val===undefined||val===null||val==='')return;
    it.val.textContent=String(val);
    it.row.style.display='';
  }
  // fillInfo 先占位固定字段顺序，异步数据到位后再填值，避免行顺序跳动。
  function fillInfo(card){
    var t=card.dataset.type, ext=fileExt(card.dataset.name);
    if(t==='image'||t==='video'||t==='audio'){
      if(ext) infoRow('fmt','格式',FMT[ext]||ext.toUpperCase());
    }
    if(t==='image') infoRow('res','分辨率');
    if(t==='video'){
      infoRow('res','分辨率');infoRow('dur','时长');infoRow('fps','帧率');infoRow('codec','编码');
    }
    if(t==='audio'){
      infoRow('dur','时长');infoRow('codec','编码');infoRow('rate','码率');infoRow('hz','采样率');
    }
    if(t==='text'){
      infoRow('lang','语言',LANG[ext]||'纯文本');
      infoRow('lines','行数');
    }
  }
  function loadMediaMeta(card,token){
    var p=card.dataset.path;
    if(!p)return;
    fetch(B+'/api/meta?path='+encodeURIComponent(p),{credentials:'same-origin'}).then(function(r){
      return r.ok?r.json():null;
    }).then(function(m){
      if(!m||token!==infoToken)return;
      if(m.fps)infoSet('fps',m.fps+' fps');
      if(m.codec)infoSet('codec',CODEC[m.codec]||m.codec.toUpperCase());
      if(m.bitrate)infoSet('rate',Math.round(m.bitrate/1000)+' kbps');
      if(m.sampleRate)infoSet('hz',fmtHz(m.sampleRate));
      if(m.duration){
        if(card.dataset.type==='video'&&m.width)infoSet('res',m.width+' × '+m.height);
        infoSet('dur',fmtDur(m.duration));
      }
    }).catch(function(){});
  }
  function refreshCards(){
    tiles=[].slice.call(grid.querySelectorAll('.file-card'));
    cards=tiles.filter(function(c){return c.dataset.type!=='folder';});
    openable=cards.filter(function(c){return c.dataset.open==='1';});
  }
  refreshCards();
  function clearBody(){if(mmCleanup){mmCleanup();mmCleanup=null;}body.innerHTML='';wmPv.classList.remove('on');wmPv.innerHTML='';}
  function blocked(msg,sub){
    clearBody();
    var box=document.createElement('div');box.className='pv-none';
    box.innerHTML='<div style="font-size:13px;color:var(--text2)">'+msg+'</div><div style="font-size:11px;color:var(--text3)">'+(sub||'')+'</div>';
    body.appendChild(box);
  }
  function guardBlocked(){
    clearBody();
    var box=document.createElement('div');box.className='pv-guard';
    box.innerHTML='<div class="guard-ico"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M12 8v4M12 15h.01"/></svg></div><b>检测到开发者工具</b><p>为避免内容被提取，已暂停该格式的在线预览。请关闭控制台后重试。</p><span>图片与 PDF 将以带水印方式显示</span>';
    body.appendChild(box);
  }
  function fillWm(el){
    var L=window.__tunhookWmLines||['TunHook','仅限在线查看'];
    var t=L.map(esc).join('<br>'),html='';
    for(var i=0;i<200;i++)html+='<span class="wm-dia"><b>'+t+'</b></span>';
    el.innerHTML='<div class="wm-diamonds">'+html+'</div>';
    el.classList.add('on');
  }
  function render(card,token){
    var t=card.dataset.type, raw=card.dataset.raw;
    clearBody();
    // 控制台打开时：图片与 PDF 继续显示（服务端/覆盖层水印），其余格式只显示提醒。
    var dev=document.body.classList.contains('devtools-open');
    if(dev&&t!=='image'&&t!=='pdf'){
      guardBlocked();
      return;
    }
    if(card.dataset.render!=='1'){
      var box=document.createElement('div');box.className='pv-none';
      var noDL=document.body.classList.contains('no-dl');
      box.innerHTML='<div class="big-ico"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg></div><div style="font-size:13px;color:var(--text2)">'+(noDL?'该分享仅允许在线查看':'此格式暂不支持在线预览')+'</div><div style="font-size:11px;color:var(--text3)">'+(noDL?'该格式无法在线预览':'可下载后使用本地应用打开')+'</div>';
      body.appendChild(box);
      return;
    }
    if(t==='image'){
      var wrap=document.createElement('div');wrap.className='img-wrap';
      var img=document.createElement('img');
      img.addEventListener('load',function(){
        if(token===infoToken&&img.naturalWidth)infoSet('res',img.naturalWidth+' × '+img.naturalHeight);
      });
      // 仅在水印模式（爬虫 / 开发者工具）下让服务端返回带水印的 SVG。
      img.src=raw;
      wrap.appendChild(img);
      var sh=document.createElement('div');sh.className='img-shield';wrap.appendChild(sh);
      body.appendChild(wrap);
    }else if(t==='video'){
      var v=document.createElement('video');v.src=raw;v.controls=true;v.autoplay=false;
      v.addEventListener('loadedmetadata',function(){
        if(token!==infoToken)return;
        if(v.videoWidth)infoSet('res',v.videoWidth+' × '+v.videoHeight);
        if(v.duration)infoSet('dur',fmtDur(v.duration));
      });
      body.appendChild(v);
      loadMediaMeta(card,token);
    }else if(t==='audio'){
      var a=document.createElement('audio');a.src=raw;a.controls=true;
      a.addEventListener('loadedmetadata',function(){
        if(token===infoToken&&a.duration)infoSet('dur',fmtDur(a.duration));
      });
      body.appendChild(a);
      loadMediaMeta(card,token);
    }else if(t==='pdf'){
      var f=document.createElement('iframe');f.src=raw;body.appendChild(f);
      if(dev)fillWm(wmPv);
    }else if(t==='text'){
      var wrap=document.createElement('div');wrap.className='code-wrap';
      var p=document.createElement('pre');p.textContent='加载中…';wrap.appendChild(p);
      body.appendChild(wrap);
      fetch(raw,{credentials:'same-origin'}).then(function(r){
        if(r.status===403)throw new Error('forbidden');
        if(!r.ok)throw new Error('http '+r.status);
        return r.text();
      }).then(function(x){
        if(!document.body.contains(wrap))return;
        if(token===infoToken)infoSet('lines',x.split('\n').length+' 行');
        p.innerHTML=highlightCode(x,card.dataset.name);
        buildMinimap(p,x);
      }).catch(function(e){p.textContent=e&&e.message==='forbidden'?'已触发内容保护，禁止查看':'读取失败';});
    }
  }
  // 轻量代码高亮：按扩展名识别注释风格，逐 token 着色，输出前统一转义。
  var HL_KW={};
  ('const let var function class extends return if else for while do switch case break continue new delete typeof instanceof in of this super import export from as async await try catch finally throw yield static get set def elif lambda pass raise with and or not is None True False package func type struct interface map chan go defer range select fallthrough nil public private protected void int long short float double bool byte char final enum implements throws true false null undefined').split(' ').forEach(function(k){HL_KW[k]=1;});
  function escapeHTMLEnt(s){return s.replace(/[&<>]/g,function(c){return c==='&'?'&amp;':c==='<'?'&lt;':'&gt;';});}
  function highlightCode(code,name){
    var ext=(String(name).split('.').pop()||'').toLowerCase();
    var hash=/^(sh|bash|zsh|fish|py|rb|ya?ml|toml|conf|ini|cfg|properties|dockerfile|makefile|mk|c|h|cpp|hpp)$/.test(ext);
    var re=hash
      ? /(\/\*[\s\S]*?\*\/|\/\/[^\n]*|#[^\n]*|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|\x60(?:\\.|[^\x60\\])*\x60|\b\d+(?:\.\d+)?\b|\b[A-Za-z_$][A-Za-z0-9_$]*\b)/g
      : /(\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|\x60(?:\\.|[^\x60\\])*\x60|\b\d+(?:\.\d+)?\b|\b[A-Za-z_$][A-Za-z0-9_$]*\b)/g;
    var out=[],last=0,m;
    while((m=re.exec(code))){
      out.push(escapeHTMLEnt(code.slice(last,m.index)));
      var tok=m[0],cls='';
      if(tok.slice(0,2)==='/*'||tok.slice(0,2)==='//')cls='com';
      else if(tok.charAt(0)==='#')cls='com';
      else if(tok.charAt(0)==='"'||tok.charAt(0)==="'"||tok.charAt(0)==='\x60')cls='str';
      else if(tok.charAt(0)>='0'&&tok.charAt(0)<='9')cls='num';
      else{
        var pc=code.charAt(m.index-1);
        var next=code.slice(m.index+tok.length,m.index+tok.length+8);
        if(pc==='<'||(pc==='/'&&code.charAt(m.index-2)==='<'))cls='tag';
        else if(/^\s*=/.test(next))cls='attr';
        else if(HL_KW[tok])cls='kw';
        else if(/^\s*\(/.test(next))cls='fn';
      }
      out.push(cls?'<span class="tok-'+cls+'">'+escapeHTMLEnt(tok)+'</span>':escapeHTMLEnt(tok));
      last=m.index+tok.length;
    }
    out.push(escapeHTMLEnt(code.slice(last)));
    return out.join('');
  }
  // buildMinimap 在文本预览右侧绘制缩略条，点击/拖动可定位，滚动时同步视口框。
  function buildMinimap(pre,text){
    var wrap=pre.parentNode;
    var mm=document.createElement('div');mm.className='code-minimap';
    var cv=document.createElement('canvas');mm.appendChild(cv);
    var box=document.createElement('div');box.className='mm-view';mm.appendChild(box);
    wrap.appendChild(mm);
    var lines=text.split('\n'), dpr=window.devicePixelRatio||1, LH=2.2, k=LH, padTop=16;
    function draw(){
      var w=cv.clientWidth, h=cv.clientHeight;
      if(w<=0||h<=0)return;
      cv.width=Math.round(w*dpr);cv.height=Math.round(h*dpr);
      var ctx=cv.getContext('2d');
      ctx.setTransform(dpr,0,0,dpr,0,0);
      ctx.clearRect(0,0,w,h);
      var total=lines.length*LH, scale=total>h?h/total:1;
      k=LH*scale;
      for(var i=0;i<lines.length;i++){
        var line=lines[i];
        if(!line.trim())continue;
        var indent=line.length-line.replace(/^\s+/,'').length;
        var x=2+Math.min(indent,12)*0.95;
        var barW=Math.min(w-x-2,Math.max(3,line.trim().length*0.95));
        var tr=line.trim(), light=document.documentElement.getAttribute('data-theme')==='light';
        var color=light?'#a9b8c8':'#3a5674';
        if(/^(\/\/|#|\/\*|\*|--)/.test(tr))color=light?'#9bbfae':'#2a5c46';
        else if(/^(func|function|class|type|const|var|let|import|package|public|private|def|return|if|for|while)\b/.test(tr))color=light?'#7d9cc0':'#5d7fa8';
        ctx.fillStyle=color;
        ctx.fillRect(x,i*k,barW,Math.max(k-0.35,0.7));
      }
      sync();
    }
    function sync(){
      var total=lines.length*k;
      var max=pre.scrollHeight-pre.clientHeight;
      var ratio=max>0?pre.scrollTop/max:0;
      var vh=Math.max(14,Math.min(total||14,(pre.clientHeight/Math.max(pre.scrollHeight,1))*total));
      box.style.height=vh+'px';
      box.style.top=(padTop+ratio*Math.max(0,total-vh))+'px';
    }
    function seek(e){
      var r=cv.getBoundingClientRect();
      if(r.height<=0)return;
      var y=Math.max(0,Math.min(r.height,e.clientY-r.top));
      pre.scrollTop=(y/r.height)*(pre.scrollHeight-pre.clientHeight);
    }
    var dragging=false;
    mm.addEventListener('pointerdown',function(e){dragging=true;if(mm.setPointerCapture)mm.setPointerCapture(e.pointerId);seek(e);e.preventDefault();});
    mm.addEventListener('pointermove',function(e){if(dragging)seek(e);});
    mm.addEventListener('pointerup',function(){dragging=false;});
    mm.addEventListener('pointercancel',function(){dragging=false;});
    pre.addEventListener('scroll',sync,{passive:true});
    var ro=null;
    if(window.ResizeObserver){ro=new ResizeObserver(function(){draw();});ro.observe(wrap);}
    mmCleanup=function(){if(ro)ro.disconnect();pre.removeEventListener('scroll',sync);};
    draw();
  }
  function open(i){
    if(i<0||i>=openable.length) return;
    var go=function(ok){
      if(i<0||i>=openable.length) return;
      cur=i;
      var c=openable[i];
      var token=++infoToken;
      extraEl.innerHTML='';infoRows={};
      nameEl.textContent=c.dataset.name;
      metaEl.textContent=c.dataset.size+' · '+c.dataset.date;
      sizeEl.textContent=c.dataset.size;
      typeEl.textContent=c.dataset.kind;
      dateEl.textContent=c.dataset.date;
      dlCountEl.textContent=c.dataset.downloads+' 次';
      dlEl.href=c.dataset.dl;
      if(dlTopEl)dlTopEl.href=c.dataset.dl;
      fillInfo(c);
      // 凭证失败也打开弹层，只显示提示，避免点击无反应。
      if(!ok) blocked('无法确认页面状态','请保持分享页在前台后重试');
      else render(c,token);
      pv.classList.add('open');
      [].forEach.call(films.children,function(b){b.classList.toggle('active',b.dataset.idx===cards.indexOf(c).toString());});
      var fi=films.querySelector('.film.active');if(fi&&fi.scrollIntoView)fi.scrollIntoView({block:'nearest',inline:'center'});
    };
    // 预览前先确认页面在场；失败时仍然打开弹层并显示提示。
    var gate=window.__tunhookEnsurePresence?window.__tunhookEnsurePresence():Promise.resolve(true);
    gate.then(function(ok){ go(ok); });
  }
  function close(){pv.classList.remove('open');clearBody();cur=-1;}
  grid.addEventListener('click',function(e){
    var card=e.target.closest('.file-card');
    if(!card||e.target.closest('a'))return;
    if(card.dataset.type==='folder'){ loadDir(card.dataset.dir); return; }
    if(card.dataset.open!=='1')return;
    var i=openable.indexOf(card); if(i>=0) open(i);
  });
  grid.addEventListener('keydown',function(e){
    if(e.key!=='Enter'&&e.key!==' ')return;
    var card=e.target.closest('.file-card');
    if(!card)return;
    e.preventDefault();
    card.click();
  });
  document.getElementById('pvClose').addEventListener('click',close);
  pv.addEventListener('click',function(e){if(e.target===pv)close();});
  films.addEventListener('click',function(e){
    var b=e.target.closest('.film'); if(!b)return;
    var idx=parseInt(b.dataset.idx,10);
    var card=cards[idx]; var i=openable.indexOf(card); if(i>=0) open(i);
  });
  document.addEventListener('keydown',function(e){
    if(!pv.classList.contains('open'))return;
    if(e.key==='Escape')close();
    else if(e.key==='ArrowLeft'){e.preventDefault();open(cur-1);}
    else if(e.key==='ArrowRight'){e.preventDefault();open(cur+1);}
  });
  var searchTimer=null, loadSeq=0;
  q.addEventListener('input',function(){
    clearTimeout(searchTimer);
    searchTimer=setTimeout(runSearch,260);
  });
  sortSel.addEventListener('change',applySort);
  crumbs.addEventListener('click',function(e){
    var b=e.target.closest('.crumb');
    if(!b||b.dataset.dir===undefined)return;
    loadDir(b.dataset.dir||'');
  });
  function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  function renderCrumbs(searching){
    if(searching){
      var back=currentDir?currentDir.split('/').pop():'全部文件';
      crumbs.innerHTML='<button type="button" class="crumb" data-dir="'+esc(currentDir)+'">'+esc(back)+'</button><span class="crumb-sep">/</span><span class="crumb active">搜索结果'+(searchLimit?' · 前 '+searchLimit+' 条':'')+'</span>';
      return;
    }
    var parts=currentDir?currentDir.split('/'):[], acc='';
    var html='<button type="button" class="crumb'+(parts.length?'':' active')+'" data-dir="">全部文件</button>';
    for(var i=0;i<parts.length;i++){
      acc=acc?acc+'/'+parts[i]:parts[i];
      html+='<span class="crumb-sep">/</span><button type="button" class="crumb'+(i===parts.length-1?' active':'')+'" data-dir="'+esc(acc)+'">'+esc(parts[i])+'</button>';
    }
    crumbs.innerHTML=html;
  }
  function applySort(){
    var k=sortSel.value;
    tiles.filter(function(c){return c.style.display!=='none';}).sort(function(a,b){
      var fa=a.dataset.type==='folder', fb=b.dataset.type==='folder';
      if(fa!==fb)return fa?-1:1;
      if(k==='name')return a.dataset.name.localeCompare(b.dataset.name,'zh');
      if(k==='size')return parseInt(b.dataset.sizeBytes,10)-parseInt(a.dataset.sizeBytes,10);
      if(k==='downloads')return parseInt(b.dataset.downloads,10)-parseInt(a.dataset.downloads,10);
      return parseInt(b.dataset.mtime,10)-parseInt(a.dataset.mtime,10);
    }).forEach(function(c){grid.appendChild(c);});
  }
  function paint(d){
    if(pv.classList.contains('open'))close();
    grid.classList.add('no-anim');
    grid.innerHTML=d.html||'';
    films.innerHTML=d.films||'';
    if(!d.count)grid.innerHTML='<div class="empty-tip">此文件夹暂无文件</div>';
    refreshCards();
    applySort();
    if(window.__tunhookLoadThumbs)window.__tunhookLoadThumbs();
  }
  function fetchTiles(url,onDone){
    var seq=++loadSeq;
    var gate=window.__tunhookEnsurePresence?window.__tunhookEnsurePresence():Promise.resolve(true);
    gate.then(function(ok){
      if(!ok)throw new Error('presence');
      return fetch(url,{credentials:'same-origin'});
    }).then(function(r){
      if(!r.ok)throw new Error('http '+r.status);
      return r.json();
    }).then(function(d){
      if(seq!==loadSeq)return;
      paint(d);
      if(onDone)onDone(d);
    }).catch(function(e){
      if(seq!==loadSeq)return;
      var msg=e&&e.message==='presence'?'请保持分享页在前台后重试':'加载失败，请刷新重试';
      grid.innerHTML='<div class="empty-tip">'+msg+'</div>';
      films.innerHTML='';
      refreshCards();
    });
  }
  function runSearch(){
    var v=q.value.trim();
    if(!v){loadDir(currentDir);return;}
    searchLimit=0;
    fetchTiles(B+'/api/search?q='+encodeURIComponent(v),function(d){
      searchLimit=d.truncated?(d.limit||0):0;
      renderCrumbs(true);
    });
  }
  function loadDir(dir){
    clearTimeout(searchTimer);
    currentDir=dir||'';
    if(q.value)q.value='';
    searchLimit=0;
    fetchTiles(B+'/api/list?dir='+encodeURIComponent(currentDir),function(){
      renderCrumbs(false);
    });
  }
  renderCrumbs(false);
  applySort();
  [].forEach.call(document.querySelectorAll('.view-toggle button'),function(b){
    b.addEventListener('click',function(){
      [].forEach.call(document.querySelectorAll('.view-toggle button'),function(x){x.classList.remove('active');});
      b.classList.add('active');
      grid.classList.toggle('list',b.dataset.view==='list');
    });
  });
  // 工具栏吸顶后按滚动距离渐显液态玻璃背景。
  // 用一个零高度锚点记录工具栏在文档中的位置：工具栏自身吸顶后 rect.top 恒为 0，无法反推。
  var tb=document.querySelector('.share-toolbar'), tbStart=-1, glassTick=false;
  var tbAnchor=null;
  if(tb){
    tbAnchor=document.createElement('div');
    tbAnchor.style.cssText='position:relative;height:0;margin:0;padding:0;pointer-events:none';
    tb.parentNode.insertBefore(tbAnchor,tb);
  }
  function measureTb(){
    if(!tb||!tbAnchor)return;
    tbStart=tbAnchor.getBoundingClientRect().top+window.pageYOffset;
    document.documentElement.style.setProperty('--tbh',tb.offsetHeight+'px');
  }
  function syncGlass(){
    if(!tb||tbStart<0)return;
    var p=(window.pageYOffset-tbStart)/110;
    document.documentElement.style.setProperty('--gp',(p<0?0:p>1?1:p).toFixed(3));
  }
  function onScroll(){
    if(glassTick)return;
    glassTick=true;
    (window.requestAnimationFrame||function(f){return setTimeout(f,16);})(function(){
      syncGlass();
      glassTick=false;
    });
  }
  window.addEventListener('scroll',onScroll,{passive:true});
  window.addEventListener('resize',function(){measureTb();syncGlass();});
  window.addEventListener('load',function(){measureTb();syncGlass();});
  measureTb();
  syncGlass();
})();
</script>`

	// 主题切换：跟随系统 / 浅色 / 深色，用户选择写入 localStorage。
	page += `<script>
(function(){
  var KEY='tunhook_share_theme',ORDER=['system','light','dark'];
  var btn=document.getElementById('themeBtn'),icon=document.getElementById('themeIcon');
  if(!btn||!icon)return;
  var mq=window.matchMedia?window.matchMedia('(prefers-color-scheme: dark)'):null;
  var ICONS={
    system:'<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    light:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    dark:'<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>'
  };
  function stored(){try{return localStorage.getItem(KEY)||'system';}catch(e){return 'system';}}
  function resolve(mode){return mode==='dark'||(mode==='system'&&mq&&mq.matches)?'dark':'light';}
  function apply(mode,persist){
    document.documentElement.setAttribute('data-theme',resolve(mode));
    icon.innerHTML=ICONS[mode]||ICONS.system;
    btn.title='主题：'+(mode==='system'?'跟随系统':mode==='light'?'浅色':'深色')+'（点击切换）';
    if(persist){try{localStorage.setItem(KEY,mode);}catch(e){}}
  }
  var mode=stored();
  if(ORDER.indexOf(mode)<0)mode='system';
  apply(mode,false);
  btn.addEventListener('click',function(){
    mode=ORDER[(ORDER.indexOf(mode)+1)%ORDER.length];
    apply(mode,true);
  });
  if(mq){
    var onSys=function(){if(stored()==='system')apply('system',false);};
    if(mq.addEventListener)mq.addEventListener('change',onSys);
    else if(mq.addListener)mq.addListener(onSys);
  }
})();
</script>`

	if noDL {
		// 页面在场证明：页面可见且屏幕尺寸正常时，前端定时向服务端换取 60 秒凭证；
		// 内容接口只认这份凭证。切到后台、锁屏或长期无心跳后凭证过期，请求按未授权处理。
		ticket := wsSharePageTicket(site, r)
		page += `<script>
(function(){
  var TICKET=` + strconv.Quote(ticket) + `;
  var B=window.__tunhookBase||'';
  var ready=false,timer=null,dtOpen=false,pending=null;
  function devNow(){
    var ow=window.outerWidth||0,oh=window.outerHeight||0;
    return ow>200&&oh>200&&((ow-window.innerWidth)>170||(oh-window.innerHeight)>170);
  }
  function visibleOK(){
    var sw=(window.screen&&window.screen.width)||0;
    var sh=(window.screen&&window.screen.height)||0;
    return document.visibilityState==='visible'&&window.innerWidth>0&&window.innerHeight>0&&sw>0&&sh>0;
  }
  function payload(dev){
    return 'ticket='+encodeURIComponent(TICKET)+'&visible=1&focus='+(document.hasFocus()?1:0)
      +'&sw='+((window.screen&&window.screen.width)||0)
      +'&sh='+((window.screen&&window.screen.height)||0)
      +'&devtools='+(dev?1:0);
  }
  function attest(dev){
    if(!visibleOK())return Promise.resolve(false);
    return fetch(B+'/__presence',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:payload(dev)})
      .then(function(r){
        if(!r.ok)return false;
        ready=true;
        if(window.__tunhookLoadThumbs)window.__tunhookLoadThumbs();
        return true;
      }).catch(function(){return false;});
  }
  function ensure(){
    if(ready&&visibleOK())return Promise.resolve(true);
    if(pending)return pending;
    pending=attest(dtOpen).then(function(ok){pending=null;return ok;});
    return pending;
  }
  window.__tunhookEnsurePresence=ensure;
  window.__tunhookLoadThumbs=function(){
    if(!ready)return;
    var imgs=document.querySelectorAll('img.thumb-img[data-src]');
    for(var i=0;i<imgs.length;i++){
      var im=imgs[i];
      if(!im.getAttribute('src'))im.setAttribute('src',im.getAttribute('data-src'));
    }
  };
  document.addEventListener('visibilitychange',function(){if(document.visibilityState==='visible')ensure();});
  window.addEventListener('focus',function(){ensure();});
  document.addEventListener('click',function(){ensure();},{passive:true});
  // 首屏先同步判断一次控制台状态，避免刷新后第一帧用错误的标记换取凭证。
  dtOpen=devNow();
  ensure();
  timer=setInterval(function(){if(visibleOK())ensure();},20000);
  window.__tunhookDevtoolsChanged=function(open){
    dtOpen=!!open;
    if(open){
      // 先把「控制台已打开」送到服务端，再强制刷新一次；同一标签页 3 秒内不重复刷新。
      try{
        if(navigator.sendBeacon)navigator.sendBeacon(B+'/__presence',new Blob([payload(true)],{type:'application/x-www-form-urlencoded'}));
      }catch(e){}
      var key='tunhook_dt_reload_'+location.pathname,last=0;
      try{last=parseInt(sessionStorage.getItem(key)||'0',10)||0;}catch(e){}
      if(Date.now()-last>3000){
        try{sessionStorage.setItem(key,String(Date.now()));}catch(e){}
        setTimeout(function(){location.reload();},80);
      }
    }else{
      try{sessionStorage.removeItem('tunhook_dt_reload_'+location.pathname);}catch(e){}
      ready=false;
      ensure();
    }
  };
})();
</script>`
		// 仅禁止下载时注入前端防护：禁用右键 / 拖拽 / 复制 / 开发者工具快捷键。
		// console 已在 <head> 中提前接管，这里不再重复处理。
		page += `<script>
(function(){
  document.addEventListener('contextmenu',function(e){e.preventDefault();},true);
  document.addEventListener('dragstart',function(e){e.preventDefault();},true);
  document.addEventListener('selectstart',function(e){e.preventDefault();},true);
  document.addEventListener('copy',function(e){e.preventDefault();},true);
  document.addEventListener('cut',function(e){e.preventDefault();},true);
  document.addEventListener('keydown',function(e){
    var k=(e.key||'').toLowerCase();
    var block=e.key==='F12'
      ||(e.ctrlKey&&e.shiftKey&&(k==='i'||k==='j'||k==='c'))
      ||(e.metaKey&&e.altKey&&(k==='i'||k==='j'||k==='c'))
      ||(e.ctrlKey&&(k==='u'||k==='s'))
      ||(e.metaKey&&(k==='u'||k==='s'));
    if(block){e.preventDefault();e.stopPropagation();}
  },true);

  // DevTools 停靠时窗口内外尺寸差会明显变大；用这个差值做轻量检测。
  // 检测到后通知在场证明脚本：强制图片水印、禁止文本预览并刷新一次。
  var devOpen=null;
  function checkDev(){
    var ow=window.outerWidth||0, oh=window.outerHeight||0;
    var open=ow>200&&oh>200&&((ow-window.innerWidth)>170||(oh-window.innerHeight)>170);
    if(open===devOpen)return;
    devOpen=open;
    document.body.classList.toggle('devtools-open',open);
    if(window.__tunhookDevtoolsChanged)window.__tunhookDevtoolsChanged(open);
  }
  checkDev();
  setInterval(checkDev,900);
})();
</script>`
	}
	page += `</body></html>`

	wsSetShareNoStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}

func boolFlag(v bool) string {
	if v {
		return "1"
	}
	return "0"
}
