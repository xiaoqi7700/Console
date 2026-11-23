// LLM 配置页共享常量与哨兵转换（page.tsx 与 profile-sheet.tsx 共用）。
// 思考开关(thinking.type)与思考强度(reasoning_effort)是两个【互相独立】的字段，
// 各自单独设置——有些接口没有 thinking 字段、只靠强度参数就能激活思考，故需解耦。
// 存库空字符串 = 该字段【不发送】；Radix Select 不接受空 value，故 UI 用 "none"
// 哨兵表示不发送，存取时与 "" 互转（NONE / fromStore / toStore）。
export const NONE = "none";
export const fromStore = (v?: string) => (v ? v : NONE);
export const toStore = (v: string) => (v === NONE ? "" : v);

export const THINKING_TYPES: { value: string; label: string }[] = [
  { value: NONE, label: "不发送（默认）" },
  { value: "disabled", label: "关闭" },
  { value: "enabled", label: "开启" },
];

// 输出上限用哪个请求字段名（仅 openai 格式有意义）。NONE ↔ "" 走同一套哨兵转换。
export const MAX_TOKENS_FIELDS: { value: string; label: string }[] = [
  { value: NONE, label: "max_tokens（默认）" },
  { value: "max_completion_tokens", label: "max_completion_tokens" },
];

// 另外两种格式各自定死了字段名，选项对它们无意义，说明文案里直接讲清楚。
export const MAX_TOKENS_FIELD_HINTS: Record<string, string> = {
  openai:
    "上限发哪个键。max_tokens 是默认，绝大多数兼容网关只认它；OpenAI 官方推理模型（o 系列 / GPT-5）反过来只认 max_completion_tokens，收到 max_tokens 会直接报 unsupported_parameter。",
  anthropic: "仅 openai 格式可选。Anthropic 的字段名固定为 max_tokens。",
  "openai-responses": "仅 openai 格式可选。Responses API 的字段名固定为 max_output_tokens。",
};

export const EFFORT_LEVELS: { value: string; label: string }[] = [
  { value: NONE, label: "不发送（默认）" },
  { value: "low", label: "low" },
  { value: "medium", label: "medium" },
  { value: "high", label: "high" },
  { value: "xhigh", label: "xhigh" },
  { value: "max", label: "max" },
];

export const CUSTOM_UA = "custom";

// LLM 请求 UA 的常用模板。选模板只是把完整 UA 填进输入框，之后仍可继续手改。
// 浏览器 UA 与编程工具（CLI/IDE）UA 是两类完全不同的特征：后者常用
// `工具名/版本 (平台; 架构) 终端` 或 `工具名/版本 sdk/... runtime/...` 的形态，
// 不少按客户端类型放行的网关只认这些前缀。模板里的版本号/终端信息可自行改。
export const UA_TOOL_PRESETS: { value: string; label: string; ua: string }[] = [
  { value: "claude-code", label: "Claude Code · CLI", ua: "claude-cli/2.1.63 (external, cli)" },
  {
    value: "codex-mac",
    label: "Codex CLI · macOS",
    ua: "codex_cli_rs/0.144.6 (Mac OS 15.6.1; arm64) ghostty/1.3.0",
  },
  {
    value: "codex-win",
    label: "Codex CLI · Windows",
    ua: "codex_cli_rs/0.144.6 (Windows 11 24H2; x86_64) vscode/1.105.1",
  },
  {
    value: "gemini-cli",
    label: "Gemini CLI",
    ua: "GeminiCLI/0.46.0/gemini-3-pro-preview (linux; x64; cli)",
  },
  {
    value: "opencode",
    label: "OpenCode",
    ua: "opencode/1.18.29 ai-sdk/openai-compatible/2.0.41 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.15",
  },
  { value: "zed", label: "Zed · AI", ua: "Zed/0.219.4+stable.119.0 (macos; aarch64)" },
  {
    value: "copilot-cli",
    label: "GitHub Copilot CLI",
    ua: "copilot/1.0.25 (client/sdk win32 v22.19.0) term/unknown",
  },
  {
    value: "copilot-vscode",
    label: "GitHub Copilot Chat · VS Code",
    ua: "GitHubCopilotChat/0.37.2026011603",
  },
  {
    value: "roo-code",
    label: "Roo Code",
    ua: "roo-code/3.45.0 (darwin 25.2.0; arm64) node/22.21.1",
  },
  {
    value: "kilo-code",
    label: "Kilo Code",
    ua: "kilo-code/5.1.0 (darwin 25.2.0; arm64) node/22.21.1",
  },
];

export const UA_BROWSER_PRESETS: { value: string; label: string; ua: string }[] = [
  {
    value: "chrome-win",
    label: "Chrome · Windows",
    ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  },
  {
    value: "chrome-mac",
    label: "Chrome · macOS",
    ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  },
  {
    value: "chrome-android",
    label: "Chrome · Android",
    ua: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
  },
  {
    value: "safari-mac",
    label: "Safari · macOS",
    ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
  },
  {
    value: "safari-iphone",
    label: "Safari · iPhone",
    ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
  },
  {
    value: "edge-win",
    label: "Edge · Windows",
    ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
  },
  {
    value: "firefox-win",
    label: "Firefox · Windows",
    ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
  },
];

// 第一项 ua="" = 不覆盖，保持 SDK/Go 默认（Go-http-client/1.1）。
export const UA_PRESETS = [
  { value: NONE, label: "不覆盖（默认 Go UA）", ua: "" },
  ...UA_TOOL_PRESETS,
  ...UA_BROWSER_PRESETS,
];

// 测试连接 / 保存后实测的原始错误 → 人话。后端 /llm/check 已做主要分类，
// 这里兜底处理 testLLM（真实推理）的原始错误文本。
export function humanizeTestError(msg: string): string {
  const m = msg || "";
  if (/\b401\b|\b403\b|invalid.*key|unauthorized/i.test(m))
    return "Key 无效或权限不足：确认 Key 是否复制完整、是否属于这个平台、账号是否还有额度。";
  if (/\b402\b|余额|欠费|quota|insufficient/i.test(m)) return "账户余额不足：先去厂商控制台充值或换免费通道。";
  if (/\b429\b|rate.?limit/i.test(m)) return "被限流：Key 有效但请求过快或额度受限，稍后重试。";
  if (/\b404\b|\b405\b|not found/i.test(m))
    return "端点路径或协议不匹配：确认 Base URL（一般以 /v1 结尾）与厂商协议是否一致——Anthropic 协议网关要选对应预设。";
  if (/timeout|deadline|refused|dns|no such host|connect/i.test(m))
    return "网络不通：检查代理设置与本机出网；域名拼写是否正确。";
  if (/model/i.test(m) && /not.*(exist|found)|invalid.*model/i.test(m))
    return "模型名不存在：回到上一步从列表里选择，或核对厂商文档的模型 ID。";
  return m || "未知错误。";
}

// 连通分诊结果 → 卡片徽章 / 保存警告的统一文案。
export const CHECK_CLASS_LABELS: Record<string, string> = {
  ok: "连通正常",
  key_invalid: "Key 无效或权限不足",
  path_or_format: "端点路径或协议不匹配",
  network: "网络不通",
  server_error: "厂商服务端错误",
  empty_list: "网关不开放模型列表（可直接手填模型名）",
  missing_key: "未填写 API Key",
  unknown: "未知错误",
};
