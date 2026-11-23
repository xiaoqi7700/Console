package report

import (
	"os"
	"path/filepath"
)

// 公文三字体（仿宋_GB2312 / 楷体_GB2312 / 方正小标宋_GBK）改为**运行期读取**，
// 不再 go:embed 进二进制。
//
// 为什么不 embed：三字体合计约 20MB，embed 后每次 go build 都要把 20MB 塞进
// 二进制——磁盘与内存都吃不消，而且字体换了就得重新编译。改成运行期从
// <数据目录>/fonts/ 读：缺失时退化为「只引用字体名」（接收方自己装了字体
// 仍能正确渲染），不会让整个导出失败。
//
// 字体文件名保持 ASCII（中文路径在跨平台构建/检出时不可靠）；TTF 内部
// family 名才是 docx 里引用的名字（fc-scan 实测）。
// 版权说明：三字体为用户提供的公文标准字体包，仅随本平台导出的报告分发。

// FontDirName 是字体目录名（相对数据目录）。
const FontDirName = "fonts"

// fontSearchDirs 是字体查找顺序：环境变量优先，其次数据目录，最后工作目录。
// 这样 Docker/单二进制部署与本地开发都能命中。
func fontSearchDirs() []string {
	var dirs []string
	if v := os.Getenv("ARTEX_FONT_DIR"); v != "" {
		dirs = append(dirs, v)
	}
	if v := os.Getenv("ARTEX_DATA_DIR"); v != "" {
		dirs = append(dirs, filepath.Join(v, FontDirName))
	}
	dirs = append(dirs, filepath.Join("data", FontDirName), FontDirName)
	return dirs
}

// gongwenFontFiles 是「docx 内引用名 → 字体文件名」的映射。
var gongwenFontFiles = []struct{ name, file string }{
	{"仿宋_GB2312", "fangsong_gb2312.ttf"},
	{"楷体_GB2312", "kaiti_gb2312.ttf"},
	{"方正小标宋_GBK", "fzxiaobiaosong_gbk.ttf"},
}

// embedGongwenFonts 把公文三字体挂到文档上。单字体缺失或读取失败只跳过
// 不报错——缺字体时退化为「引用字体名」（接收方装了字体仍正常），
// 不能让整个导出失败。
func embedGongwenFonts(d *Docx) {
	dirs := fontSearchDirs()
	for _, e := range gongwenFontFiles {
		for _, dir := range dirs {
			b, err := os.ReadFile(filepath.Join(dir, e.file))
			if err != nil {
				continue
			}
			d.EmbedFont(e.name, b)
			break
		}
	}
}

// GongwenFontsAvailable 报告三字体里能读到几个（状态页/排障用）。
func GongwenFontsAvailable() int {
	n := 0
	dirs := fontSearchDirs()
	for _, e := range gongwenFontFiles {
		for _, dir := range dirs {
			if _, err := os.Stat(filepath.Join(dir, e.file)); err == nil {
				n++
				break
			}
		}
	}
	return n
}