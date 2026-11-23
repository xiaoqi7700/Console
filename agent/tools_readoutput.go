package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// read_output（v0.4.92 验证层冲刺）：按行窗口回读「SDK 超长输出落盘文件」。
//
// 背景：工具输出超长时 norma 把全量落盘到 runDir/cmd-output/ 并在回显头部给绝对
// 路径指针——此前模型只能用 Bash cat/sed 回读（整段往返、易读错路径）。本工具：
// 路径限定在 cmd-output 目录内（basename 校验防越界）、按行窗口取用、自带总行数
// 元数据，省 token 且不丢信息（「可回读的省略」哲学的收口件）。
func (t *ToolSet) readOutput() actool.CoreTool {
	return readTool(
		"read_output",
		"按行窗口回读「工具超长输出落盘文件」（工具回显头部指出的 cmd-output/ 下路径）。"+
			"大文件先看总行数与头部摘要，再用 offset/lines 翻页定位关键段；比用 Bash cat 省 token。"+
			"文件名只需给 cmd-output/ 下的文件名（自动限定目录，防越界）。",
		obj(map[string]any{
			"file":   str("落盘文件名（如 output-1730000000-1.txt；也接受回显头部给的完整路径）"),
			"offset": intp("起始行号（1 基），默认 1"),
			"lines":  intp("返回行数，默认 100，最大 500"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				File   string `json:"file"`
				Offset int    `json:"offset"`
				Lines  int    `json:"lines"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("参数解析失败: %v", err)), nil
			}
			if strings.TrimSpace(a.File) == "" {
				return actool.Errorf("file 必填（回显头部指出的落盘文件路径或文件名）"), nil
			}
			// 路径夹逼：只允许 basename，落到本 run 的 cmd-output 目录内。
			name := filepath.Base(strings.TrimSpace(a.File))
			if t.runDir == "" {
				return actool.Errorf("当前 run 没有工作目录（read_output 仅在配置了 ToolOutputDir 的 agent 可用）"), nil
			}
			path := filepath.Join(cmdOutDir(t.runDir), name)
			f, err := os.Open(path)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("文件不存在或不可读（%s）：%v。注意：只回读本 run 的 cmd-output 落盘文件", name, err)), nil
			}
			defer f.Close()

			offset := a.Offset
			if offset < 1 {
				offset = 1
			}
			limit := a.Lines
			if limit <= 0 {
				limit = 100
			}
			if limit > 500 {
				limit = 500
			}
			var (
				all   []string
				bytes int64
			)
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // 单行上限 4MB（对齐单文件限额）
			for sc.Scan() {
				all = append(all, sc.Text())
				bytes += int64(len(sc.Bytes())) + 1
			}
			if err := sc.Err(); err != nil {
				return actool.Errorf(fmt.Sprintf("读取失败: %v", err)), nil
			}
			total := len(all)
			if offset > total {
				return actool.Text(fmt.Sprintf("offset %d 超出总行数 %d（文件 %d 字节）；用 offset=%d 读尾部。", offset, total, bytes, max(total-limit+1, 1))), nil
			}
			end := min(offset+limit-1, total)
			var b strings.Builder
			fmt.Fprintf(&b, "文件 %s：共 %d 行，%d 字节；显示第 %d–%d 行。\n", name, total, bytes, offset, end)
			for i := offset; i <= end; i++ {
				fmt.Fprintf(&b, "%d: %s\n", i, all[i-1])
			}
			if end < total {
				fmt.Fprintf(&b, "（还有 %d 行未显示；用 offset=%d 翻下一页）", total-end, end+1)
			}
			return actool.Text(b.String()), nil
		})
}
