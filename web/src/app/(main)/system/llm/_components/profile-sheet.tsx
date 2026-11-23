"use client";

import * as React from "react";

import {
  ArrowLeftIcon,
  ArrowRightIcon,
  CheckIcon,
  ChevronDownIcon,
  EyeIcon,
  EyeOffIcon,
  Loader2Icon,
  PlugZapIcon,
  RefreshCwIcon,
  SaveIcon,
  SparklesIcon,
  ZapIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import type { LLMCheckResult, LLMPreset, LLMProfile, LLMRetryOverride } from "@/lib/types";
import { cn } from "@/lib/utils";

import { ProfileRetryFields, ZERO_OVERRIDE } from "./retry";
import {
  CHECK_CLASS_LABELS,
  CUSTOM_UA,
  EFFORT_LEVELS,
  MAX_TOKENS_FIELDS,
  MAX_TOKENS_FIELD_HINTS,
  NONE,
  THINKING_TYPES,
  UA_BROWSER_PRESETS,
  UA_PRESETS,
  UA_TOOL_PRESETS,
  fromStore,
  humanizeTestError,
  toStore,
} from "./shared";

const CATEGORY_LABELS: Record<string, string> = {
  official: "官方",
  aggregate: "聚合",
  relay: "中转",
  local: "本地",
  custom: "自定义",
};

const CATEGORY_DOTS: Record<string, string> = {
  official: "bg-emerald-500",
  aggregate: "bg-sky-500",
  relay: "bg-amber-500",
  local: "bg-violet-500",
  custom: "bg-amber-500",
};

const FORMAT_LABELS: Record<string, string> = {
  anthropic: "Anthropic 协议",
  openai: "OpenAI 协议",
  "openai-responses": "OpenAI Responses 协议",
};

export function ProfileSheet({
  profile,
  open,
  onOpenChange,
  onSaved,
}: {
  profile: LLMProfile | null; // null = 新建（走三步向导）
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onSaved: (id: string) => void;
}) {
  const isNew = !profile;
  // ── 向导状态（仅新建） ──
  const [step, setStep] = React.useState(1);
  const [presets, setPresets] = React.useState<LLMPreset[]>([]);
  const [presetId, setPresetId] = React.useState("");
  const [presetSearch, setPresetSearch] = React.useState("");
  const [presetCategory, setPresetCategory] = React.useState<"all" | string>("all");
  // ── 核心字段 ──
  const [name, setName] = React.useState("");
  const [format, setFormat] = React.useState<"anthropic" | "openai" | "openai-responses">("anthropic");
  const [model, setModel] = React.useState("");
  const [baseUrl, setBaseUrl] = React.useState("");
  const [proxy, setProxy] = React.useState("");
  const [apiKey, setApiKey] = React.useState("");
  const [keyHint, setKeyHint] = React.useState("");
  const [cw, setCw] = React.useState("0"); // 上下文窗口(K tokens)
  const [cwTouched, setCwTouched] = React.useState(false);
  const [mtfTouched, setMtfTouched] = React.useState(false);
  const [maxTokensTouched, setMaxTokensTouched] = React.useState(false); // 用户手动改过就不再被自动推断覆盖
  const [presetIdStore, setPresetIdStore] = React.useState("");
  // ── 高级字段（两种模式共用） ──
  const [rps, setRps] = React.useState("0");
  const [rpm, setRpm] = React.useState("0");
  const [thinkingType, setThinkingType] = React.useState(NONE);
  const [effort, setEffort] = React.useState(NONE);
  const [priority, setPriority] = React.useState("0");
  const [poolExclude, setPoolExclude] = React.useState(false);
  const [streaming, setStreaming] = React.useState(true);
  const [maxTokens, setMaxTokens] = React.useState("0");
  const [maxTokensField, setMaxTokensField] = React.useState(NONE);
  const [sessionHeaderKey, setSessionHeaderKey] = React.useState("");
  const [userAgent, setUserAgent] = React.useState("");
  const [retry, setRetry] = React.useState<LLMRetryOverride>(ZERO_OVERRIDE);
  const [advOpen, setAdvOpen] = React.useState(false);
  // ── 模型列表 ──
  const [models, setModels] = React.useState<string[]>([]);
  const [modelsSource, setModelsSource] = React.useState<"" | "fetched" | "preset">("");
  const [loadingModels, setLoadingModels] = React.useState(false);
  const [modelsOpen, setModelsOpen] = React.useState(false);
  // ── 保存/测试 ──
  const [saveAndActivate, setSaveAndActivate] = React.useState(true);
  const [testing, setTesting] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [showKey, setShowKey] = React.useState(false);
  // ── 草稿关闭确认 ──
  const [confirmClose, setConfirmClose] = React.useState(false);
  const initialRef = React.useRef("");

  const profileId = profile ? Number(profile.id) : undefined;
  const uaPresetValue = UA_PRESETS.find((p) => p.ua === userAgent)?.value ?? CUSTOM_UA;
  const activePreset = presets.find((p) => p.id === presetId);

  const coreSnapshot = () =>
    JSON.stringify({
      name, format, model, baseUrl, proxy, apiKey, cw, rps, rpm, thinkingType, effort,
      priority, poolExclude, streaming, maxTokens, maxTokensField, sessionHeaderKey, userAgent,
      retry, presetId: presetIdStore,
    });
  const dirty = open && coreSnapshot() !== initialRef.current;

  // 每次打开重灌表单；新建重置向导到第 1 步并拉预设。
  React.useEffect(() => {
    if (!open) return;
    const p = profile;
    setName(p?.name ?? "");
    setFormat(p?.format === "openai" || p?.format === "openai-responses" ? p.format : "anthropic");
    setModel(p?.model ?? "");
    setBaseUrl(p?.base_url ?? "");
    setProxy(p?.proxy ?? "");
    setCw(String(p?.context_window_k ?? 0));
    setCwTouched(false);
    setPresetIdStore(p?.preset_id ?? "");
    setPresetId(p?.preset_id ?? "");
    setRps(String(p?.rate_per_second ?? 0));
    setRpm(String(p?.rate_per_minute ?? 0));
    setThinkingType(fromStore(p?.thinking_type));
    setEffort(fromStore(p?.reasoning_effort));
    setPriority(String(p?.priority ?? 0));
    setPoolExclude(p?.pool_exclude ?? false);
    setStreaming(p?.streaming ?? true);
    setMaxTokens(String(p?.max_tokens ?? 0));
    setMaxTokensTouched(false);
    setMaxTokensField(fromStore(p?.max_tokens_field));
    setMtfTouched(false);
    setSessionHeaderKey(p?.session_header_key ?? "");
    setUserAgent(p?.user_agent ?? "");
    setRetry(p?.retry ?? ZERO_OVERRIDE);
    setApiKey("");
    setKeyHint(p?.api_key_hint ?? "");
    setModels([]);
    setModelsSource("");
    setModelsOpen(false);
    setSaveAndActivate(true);
    setStep(1);
    setPresetSearch("");
    setAdvOpen(false);
    // 状态批量更新后落定初始快照（dirty 检测基线）
    const t = setTimeout(() => {
      initialRef.current = coreSnapshot();
    }, 0);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, profile]);

  // 新建模式拉预设清单
  React.useEffect(() => {
    if (!open || !isNew) return;
    api
      .llmPresets()
      .then((r) => setPresets(r.presets ?? []))
      .catch(() => toast.error("厂商预设加载失败：可直接选「自定义中转站」手动填写"));
  }, [open, isNew]);

  const handleClose = (o: boolean) => {
    if (!o && dirty) {
      setConfirmClose(true); // 有未保存草稿：先确认
      return;
    }
    onOpenChange(o);
  };

  // ── 模型列表：在线拉取，失败回退厂商预设清单（one-api 教训：预置+在线结合） ──
  async function loadModels() {
    if (loadingModels) return;
    setLoadingModels(true);
    setModels([]);
    setModelsSource("");
    try {
      const r = await api.fetchLLMModels(format, baseUrl, apiKey, proxy, profileId, userAgent.trim());
      if (r.ok && r.models && r.models.length > 0) {
        setModels(r.models);
        setModelsSource("fetched");
        setModelsOpen(true);
        toast.success(`已加载 ${r.models.length} 个模型`);
      } else {
        fallbackModels(r.error ?? "未获取到模型");
      }
    } catch (e) {
      fallbackModels((e as Error).message);
    } finally {
      setLoadingModels(false);
    }
  }
  function fallbackModels(reason: string) {
    const pm = activePreset?.models.map((m) => m.id) ?? [];
    if (pm.length > 0) {
      setModels(pm);
      setModelsSource("preset");
      setModelsOpen(true);
      toast.warning(`在线拉取失败（${reason}），已显示预置模型；也可直接手填`);
    } else {
      toast.error(`加载模型失败：${reason}；可直接手填模型名`);
    }
  }

  // 选模型后自动推断 context window（用户手动改过则不覆盖）
  async function pickModel(m: string) {
    setModel(m);
    setModelsOpen(false);
    try {
      const meta = await api.llmModelMeta(m);
      // context 自动填（用户手动改过则不覆盖）
      if (!cwTouched && meta.source !== "none" && meta.context_k > 0) setCw(String(meta.context_k));
      // 上限字段名自动推断（v0.4.93）：openai 格式 + reasoning 模型 → max_completion_tokens
      if (!mtfTouched && format === "openai" && meta.reasoning) setMaxTokensField("max_completion_tokens");
      // 模型级参数覆盖（v0.4.96，对照内部版 v0.9.64）：选中的列表模型自带预设级参数时应用
      const me = activePreset?.models.find((mm) => mm.id.toLowerCase() === m.toLowerCase());
      if (me) {
        if (!cwTouched && me.context_k > 0) setCw(String(me.context_k));
        if (me.max_tokens) setMaxTokens(String(me.max_tokens));
        if (me.max_tokens_field) setMaxTokensField(fromStore(me.max_tokens_field));
        if (me.thinking_type) setThinkingType(fromStore(me.thinking_type));
        if (me.reasoning_effort) setEffort(fromStore(me.reasoning_effort));
        if (me.user_agent) setUserAgent(me.user_agent);
      }
    } catch {
      /* 推断失败静默：不影响手填 */
    }
  }

  async function testConnection() {
    if (testing) return;
    if (!model.trim()) {
      toast.error("先填写模型名再测试");
      return;
    }
    setTesting(true);
    try {
      const r = await api.testLLM(
        format, model, baseUrl, apiKey, proxy,
        toStore(thinkingType), toStore(effort), profileId,
        streaming, sessionHeaderKey.trim(), userAgent.trim(),
      );
      if (r.ok)
        toast.success(`连接成功 · ${r.latency_ms ?? "?"}ms · ${r.model ?? model}`, {
          description: r.reply ? `回复：${r.reply}` : undefined,
        });
      else toast.error(`连接失败：${humanizeTestError(r.error ?? "")}`, { duration: 10000 });
    } catch (e) {
      toast.error(`测试出错：${humanizeTestError((e as Error).message)}`, { duration: 10000 });
    } finally {
      setTesting(false);
    }
  }

  // ── 保存：落库（+激活）→ 连通分诊 → 真实推理；失败不阻止保存但讲人话 ──
  async function save(andActivate: boolean) {
    if (!name.trim() || !model.trim()) {
      toast.error("请填写名称与模型");
      return;
    }
    if (saving) return;
    setSaving(true);
    try {
      const { id } = await api.saveLLMProfile({
        ...(profile ? { id: Number(profile.id) } : {}),
        name: name.trim(),
        format,
        model: model.trim(),
        base_url: baseUrl.trim(),
        proxy: proxy.trim(),
        api_key: apiKey,
        rate_per_second: Number(rps) || 0,
        rate_per_minute: Number(rpm) || 0,
        context_window_k: Number(cw) || 0,
        thinking_type: toStore(thinkingType),
        reasoning_effort: toStore(effort),
        priority: Number(priority) || 0,
        pool_exclude: poolExclude,
        streaming,
        max_tokens: Math.max(0, Number(maxTokens) || 0),
        // 字段名开关只对 openai(Chat Completions) 有意义，其它格式一律回落默认；
        // 后端会再做一次同样的归一化，这里只是别让 UI 送出自相矛盾的值。
        max_tokens_field: format === "openai" ? toStore(maxTokensField) : "",
        session_header_key: sessionHeaderKey.trim(),
        user_agent: userAgent.trim(),
        retry,
        preset_id: presetIdStore,
      });
      if (andActivate && isNew) {
        try {
          await api.activateLLMProfile(String(id));
        } catch (e) {
          toast.error(`已保存但激活失败：${(e as Error).message}；可在卡片上「设为激活」`);
        }
      }
      toast.success(
        isNew
          ? andActivate
            ? `已新建并激活：${name.trim()}`
            : `已新建：${name.trim()}（在卡片上「设为激活」以启用）`
          : profile?.is_default
            ? "已保存，激活配置即时生效，无需重启"
            : "已保存",
      );
      // 保存成功 ≠ 跑得通。两层自动验证（失败不阻止——配置已生效）：
      // 1) /llm/check 拉模型列表 → key 无效 / 协议路径错 / 网络不通分诊
      // 2) /llm/test 真实推理 → 最终验收
      const pid = profile ? profileId : Number(id);
      try {
        const c: LLMCheckResult = await api.llmCheck(format, baseUrl.trim(), apiKey, proxy.trim(), pid, userAgent.trim());
        if (!c.ok && (c.status_class === "key_invalid" || c.status_class === "network" || c.status_class === "missing_key")) {
          // 模型列表不可用≠不可用（网关可不开放列表），但 key/网络类问题立刻讲清楚
          toast.warning(`已保存，但连通检查未通过：${c.error_human ?? CHECK_CLASS_LABELS[c.status_class]}`, {
            duration: 12000,
          });
          onSaved(String(id));
          onOpenChange(false);
          return;
        }
        const t = await api.testLLM(
          format, model.trim(), baseUrl.trim(), apiKey, proxy.trim(),
          toStore(thinkingType), toStore(effort), pid,
          streaming, sessionHeaderKey.trim(), userAgent.trim(),
        );
        if (!t.ok) {
          toast.error(`已保存，但实测失败：${humanizeTestError(t.error ?? "")}`, { duration: 12000 });
        }
      } catch {
        // 验证请求本身失败不该掩盖「保存成功」——配置已生效。
      }
      onSaved(String(id));
      onOpenChange(false);
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  // ── 向导第 1 步：厂商卡片过滤 ──
  const presetCategories = React.useMemo(() => {
    const seen: { key: string; label: string }[] = [];
    for (const p of presets) {
      if (!seen.some((c) => c.key === p.category)) seen.push({ key: p.category, label: CATEGORY_LABELS[p.category] ?? p.category });
    }
    return seen;
  }, [presets]);
  const filteredPresets = presets.filter((p) => {
    if (presetCategory !== "all" && p.category !== presetCategory) return false;
    const q = presetSearch.trim().toLowerCase();
    if (!q) return true;
    return p.name.toLowerCase().includes(q) || p.base_url.toLowerCase().includes(q) || p.id.includes(q);
  });
  function pickPreset(p: LLMPreset) {
    setPresetId(p.id);
    setPresetIdStore(p.id);
    setFormat(p.format);
    setBaseUrl(p.base_url);
    // 差异化 profile 参数预置（v0.4.93）：会话头/UA/上限字段名随预设带入，
    // 「填 Key 即可用」——用户不必进高级设置手动配。
    setSessionHeaderKey(p.session_header_key ?? "");
    setUserAgent(p.user_agent ?? "");
    setMaxTokensField(p.max_tokens_field ? fromStore(p.max_tokens_field) : NONE);
    setMtfTouched(false);
    setMaxTokens(p.max_tokens ? String(p.max_tokens) : "");
    setMaxTokensTouched(false);
    setThinkingType(fromStore(p.thinking_type));
    setEffort(fromStore(p.reasoning_effort));
    // 名称自动带出（当前没起名或起的正是某预设名时才覆盖）
    if (!name.trim() || presets.some((x) => x.name === name.trim())) setName(p.name);
    setModels([]); // 换厂商后旧列表失效
    setModelsSource("");
  }

  const nameInvalid = !name.trim();
  const modelInvalid = !model.trim() && (!isNew || step >= 3);

  // ── 共享渲染片段 ──
  const nameField = (
    <div className="grid gap-2">
      <Label htmlFor="p-name">
        名称 <span className="text-destructive">*</span>
      </Label>
      <Input
        id="p-name"
        placeholder="例如：OpenAI 生产 / OpenCode 主力"
        value={name}
        onChange={(e) => setName(e.target.value)}
        className={cn(nameInvalid && "border-destructive")}
      />
    </div>
  );

  const modelField = (
    <div className="grid gap-2">
      <Label htmlFor="p-model">
        模型 <span className="text-destructive">*</span>
      </Label>
      <div className="flex gap-2">
        <Input
          id="p-model"
          className={cn("font-mono", modelInvalid && "border-destructive")}
          placeholder="从列表选择或手填模型 ID"
          value={model}
          onChange={(e) => setModel(e.target.value)}
        />
        {/* modal: Popover 内容被 portal 到 <body>，在 Sheet 滚动锁之外，
            不加 modal 列表能渲染却滚不动。modal 让它自己持有最上层滚动锁。 */}
        <Popover open={modelsOpen} onOpenChange={setModelsOpen} modal>
          <PopoverTrigger asChild>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="shrink-0 whitespace-nowrap"
              disabled={loadingModels}
              onClick={loadModels}
              title="在线拉取可用模型；失败时回退厂商预置清单"
            >
              {loadingModels ? <Loader2Icon className="animate-spin" /> : <RefreshCwIcon />}
              {modelsSource === "preset" ? "预置" : "拉取模型"}
            </Button>
          </PopoverTrigger>
          {models.length > 0 && (
            <PopoverContent className="max-h-72 w-72 gap-0 overflow-y-auto overscroll-contain p-1" align="end">
              {modelsSource === "preset" && (
                <p className="px-2 py-1 text-muted-foreground text-[11px]">在线拉取不可用，以下为厂商预置清单</p>
              )}
              {models.map((m) => (
                <button
                  key={m}
                  type="button"
                  className="w-full shrink-0 rounded-md px-2 py-1.5 text-left font-mono text-xs hover:bg-accent hover:text-accent-foreground"
                  onClick={() => void pickModel(m)}
                >
                  {m}
                </button>
              ))}
            </PopoverContent>
          )}
        </Popover>
      </div>
    </div>
  );

  const baseUrlField = (
    <div className="grid gap-2">
      <Label htmlFor="p-base-url">Base URL{isNew && presetId === "custom-relay" ? <span className="text-destructive"> *</span> : ""}</Label>
      <Input
        id="p-base-url"
        className="font-mono"
        placeholder="https://api.openai.com/v1（以厂商文档为准）"
        value={baseUrl}
        onChange={(e) => setBaseUrl(e.target.value)}
      />
      {activePreset?.format === "anthropic" && (
        <p className="text-muted-foreground text-xs">该厂商走 Anthropic 协议（x-api-key 头），地址已按官方端点带出。</p>
      )}
    </div>
  );

  const proxyField = (
    <div className="grid gap-2">
      <Label htmlFor="p-proxy">代理（可选）</Label>
      <Input
        id="p-proxy"
        className="font-mono"
        placeholder="socks5://user:pass@127.0.0.1:1080 · http://127.0.0.1:8080"
        value={proxy}
        onChange={(e) => setProxy(e.target.value)}
      />
      <p className="text-muted-foreground text-xs">
        仅 LLM 出站请求走此代理，支持 http/https/socks5，可带账号密码（密码含特殊字符需 URL
        编码）；留空表示直连。
      </p>
    </div>
  );

  const keyField = (
    <div className="grid gap-2">
      <Label htmlFor="p-key">
        API Key{isNew ? <span className="text-destructive"> *</span> : <span className="text-muted-foreground text-xs">（留空 = 保持不变）</span>}
      </Label>
      <div className="relative">
        <Input
          id="p-key"
          type={showKey ? "text" : "password"}
          autoComplete="off"
          placeholder={isNew ? "粘贴厂商控制台的 Key" : keyHint ? `已存 Key（${keyHint}），留空保持不变` : "粘贴 Key"}
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          className="pr-10"
        />
        <button
          type="button"
          onClick={() => setShowKey(!showKey)}
          className="absolute top-1/2 right-2.5 -translate-y-1/2 text-muted-foreground transition-colors hover:text-foreground"
          aria-label={showKey ? "隐藏 Key" : "显示 Key"}
          title={showKey ? "隐藏 Key" : "显示 Key"}
        >
          {showKey ? <EyeOffIcon className="size-4" /> : <EyeIcon className="size-4" />}
        </button>
      </div>
      {activePreset?.auth_note && <p className="text-muted-foreground text-xs">{activePreset.auth_note}</p>}
    </div>
  );

  const cwField = (() => {
    const k = Number(cw) || 0;
    const metaKnown = activePreset?.models.find((m) => m.id.toLowerCase() === model.trim().toLowerCase());
    const hint = cwTouched
      ? "手动填写的窗口值。"
      : k > 0
        ? `自动识别：约 ${k}K tokens${metaKnown ? "（厂商预设）" : "（模型元数据）"}，可手动覆盖。`
        : "未识别该模型的窗口：留空按默认处理，建议从厂商文档查到后填入精确值。";
    return (
      <div className="grid gap-2">
        <Label htmlFor="p-cw">上下文窗口（K tokens，可选）</Label>
        <Input
          id="p-cw"
          inputMode="numeric"
          placeholder="如 200 / 128"
          value={cw === "0" ? "" : cw}
          onChange={(e) => {
            setCw(e.target.value.replace(/[^0-9]/g, ""));
            setCwTouched(true);
          }}
        />
        <p className="flex items-start gap-1.5 rounded-md bg-muted/50 px-2 py-1.5 text-muted-foreground text-xs">
          <SparklesIcon className="mt-0.5 size-3 shrink-0 text-primary" />
          <span>{hint}</span>
        </p>
      </div>
    );
  })();

  // 高级设置折叠区（极客参数都收进来；两模式共用）
  const advancedSection = (
    <Collapsible open={advOpen} onOpenChange={setAdvOpen} className="rounded-lg border">
      <CollapsibleTrigger className="group flex w-full items-center justify-between px-3 py-2 text-sm font-medium">
        高级设置（限速 / 思考参数 / 轮询顺位 / 重试覆盖…）
        <ChevronDownIcon className="size-4 text-muted-foreground transition-transform group-data-[state=open]:rotate-180" />
      </CollapsibleTrigger>
      <CollapsibleContent className="grid gap-4 border-t px-3 py-3">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="p-rps">每秒请求上限（0=不限）</Label>
            <Input id="p-rps" inputMode="decimal" value={rps} onChange={(e) => setRps(e.target.value)} />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="p-rpm">每分钟请求上限（0=不限）</Label>
            <Input id="p-rpm" inputMode="decimal" value={rpm} onChange={(e) => setRpm(e.target.value)} />
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="p-thinking">思考开关（thinking.type）</Label>
            <Select value={thinkingType} onValueChange={setThinkingType}>
              <SelectTrigger id="p-thinking">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {THINKING_TYPES.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="p-effort">思考强度（reasoning_effort）</Label>
            <Select value={effort} onValueChange={setEffort}>
              <SelectTrigger id="p-effort">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {EFFORT_LEVELS.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="p-max-tokens">单次回复输出上限（0=不发送）</Label>
            <Input id="p-max-tokens" inputMode="numeric" value={maxTokens} onChange={(e) => setMaxTokens(e.target.value)} />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="p-mtf">输出上限字段名（仅 OpenAI 协议）</Label>
            <Select
              value={maxTokensField}
              onValueChange={(v) => {
                setMaxTokensField(v);
                setMtfTouched(true);
              }}
              disabled={format !== "openai"}
            >
              <SelectTrigger id="p-mtf">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {MAX_TOKENS_FIELDS.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-muted-foreground text-xs">{MAX_TOKENS_FIELD_HINTS[format] ?? ""}</p>
          </div>
        </div>

        <div className="flex items-center justify-between gap-4 rounded-md border px-3 py-2">
          <div>
            <Label htmlFor="p-streaming">流式输出（SSE）</Label>
            <p className="text-muted-foreground text-xs">
              开启=流式（可看实时进度）；关闭=非流式（整段返回，绕开部分网关不稳定的 SSE，代价是没有过程进度）。
            </p>
          </div>
          <Switch id="p-streaming" checked={streaming} onCheckedChange={setStreaming} />
        </div>

        <div className="grid gap-2">
          <Label htmlFor="p-session-header">自定义会话头（可选）</Label>
          <Input
            id="p-session-header"
            className="font-mono"
            placeholder="如 x-session-id（留空=不发送）"
            value={sessionHeaderKey}
            onChange={(e) => setSessionHeaderKey(e.target.value)}
          />
          <p className="text-muted-foreground text-xs">
            填写后每次请求带该 HTTP 头，头值自动填为当前会话的 session id。用于按 session-id
            做提示缓存 / 粘性路由的网关；留空不发送。
          </p>
        </div>

        <div className="grid gap-2">
          <Label htmlFor="p-ua">LLM 请求 User-Agent（可选）</Label>
          <Select
            value={uaPresetValue}
            onValueChange={(v) => {
              const preset = UA_PRESETS.find((x) => x.value === v);
              if (preset) setUserAgent(preset.ua);
            }}
          >
            <SelectTrigger id="p-ua">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectLabel>编程工具（按客户端放行的网关用）</SelectLabel>
                {UA_PRESETS.filter((p) => p.value !== NONE && p.value !== CUSTOM_UA).map((p) =>
                  UA_TOOL_PRESETS.some((t) => t.value === p.value) ? (
                    <SelectItem key={`tool-${p.value}`} value={p.value}>
                      {p.label}
                    </SelectItem>
                  ) : null,
                )}
              </SelectGroup>
              <SelectGroup>
                <SelectLabel>浏览器（WAF 拦 Go UA 时用）</SelectLabel>
                {UA_BROWSER_PRESETS.map((p) => (
                  <SelectItem key={p.value} value={p.value}>
                    {p.label}
                  </SelectItem>
                ))}
              </SelectGroup>
              <SelectItem value={NONE}>不覆盖（默认 Go UA）</SelectItem>
              <SelectItem value={CUSTOM_UA}>自定义（手输）</SelectItem>
            </SelectContent>
          </Select>
          <Input
            className="font-mono text-xs"
            placeholder="自定义 User-Agent（选了模板会自动填入，可再改）"
            value={userAgent}
            onChange={(e) => setUserAgent(e.target.value)}
          />
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="p-priority">轮询优先级（数字越大越先）</Label>
            <Input id="p-priority" inputMode="numeric" value={priority} onChange={(e) => setPriority(e.target.value)} />
            <p className="text-muted-foreground text-xs">激活配置恒为第 1 顺位，与本值无关；相同优先级轮流打头。</p>
          </div>
          <div className="flex items-center justify-between gap-4 rounded-md border px-3 py-2">
            <div>
              <Label htmlFor="p-pool-exclude">不参与轮询</Label>
              <p className="text-muted-foreground text-xs">不作为故障转移目标，但仍可被 Agent / 任务显式指定。</p>
            </div>
            <Switch id="p-pool-exclude" checked={poolExclude} onCheckedChange={setPoolExclude} />
          </div>
        </div>

        <ProfileRetryFields value={retry} onChange={setRetry} />
      </CollapsibleContent>
    </Collapsible>
  );

  return (
    <Sheet open={open} onOpenChange={handleClose}>
      <SheetContent side="right" className="flex w-full! max-w-none! flex-col gap-0 p-0 sm:min-w-[420px]! sm:max-w-xl!">
        <SheetHeader className="px-4">
          <SheetTitle className="flex items-center gap-2">
            {isNew ? "新建模型配置" : `编辑：${profile?.name}`}
            {profile?.is_default && (
              <Badge variant="outline" className="border-amber-400/50 text-amber-500">
                激活中
              </Badge>
            )}
          </SheetTitle>
          <SheetDescription>
            {isNew
              ? "三步完成：选厂商 → 粘 Key → 选模型。保存后自动验证连通性。"
              : "修改后点击保存；激活配置保存后对全部 Agent 立即生效。"}
          </SheetDescription>
        </SheetHeader>

        <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-4">
          {isNew ? (
            <>
              {/* 步骤指示：编号圆点 + 完成勾 + 连线 */}
              <div className="flex items-center gap-1.5">
                {["选厂商", "填凭据", "选模型"].map((label, i) => {
                  const n = i + 1;
                  const done = step > n;
                  const active = step === n;
                  return (
                    <React.Fragment key={label}>
                      {i > 0 && <div className={cn("h-px w-6", done ? "bg-primary/60" : "bg-border")} />}
                      <div className="flex items-center gap-1.5">
                        <span
                          className={cn(
                            "flex size-5 items-center justify-center rounded-full text-[10px] font-semibold transition-colors",
                            done && "bg-primary text-primary-foreground",
                            active && "border-2 border-primary text-primary",
                            !done && !active && "border border-border text-muted-foreground",
                          )}
                        >
                          {done ? <CheckIcon className="size-3" /> : n}
                        </span>
                        <span className={cn("text-xs", active ? "font-medium text-foreground" : "text-muted-foreground")}>
                          {label}
                        </span>
                      </div>
                    </React.Fragment>
                  );
                })}
              </div>

              {step === 1 && (
                <>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => setPresetCategory("all")}
                      className={cn(
                        "rounded-full border px-2.5 py-1 text-xs transition-colors",
                        presetCategory === "all"
                          ? "border-primary bg-primary/10 text-primary"
                          : "text-muted-foreground hover:border-primary/40 hover:text-foreground",
                      )}
                    >
                      全部（{presets.length}）
                    </button>
                    {presetCategories.map((c) => (
                      <button
                        key={c.key}
                        type="button"
                        onClick={() => setPresetCategory(c.key)}
                        className={cn(
                          "rounded-full border px-2.5 py-1 text-xs transition-colors",
                          presetCategory === c.key
                            ? "border-primary bg-primary/10 text-primary"
                            : "text-muted-foreground hover:border-primary/40 hover:text-foreground",
                        )}
                      >
                        {c.label}
                      </button>
                    ))}
                  </div>
                  <Input
                    placeholder="搜索厂商名称或域名…"
                    value={presetSearch}
                    onChange={(e) => setPresetSearch(e.target.value)}
                  />
                  <div className="grid gap-2 sm:grid-cols-2">
                    {filteredPresets.map((p) => {
                      const selected = presetId === p.id;
                      const dot = CATEGORY_DOTS[p.category] ?? "bg-amber-500";
                      return (
                        <button
                          key={p.id}
                          type="button"
                          onClick={() => pickPreset(p)}
                          className={cn(
                            "relative rounded-lg border p-3 text-left transition-all hover:border-primary/50 hover:shadow-sm",
                            selected && "border-primary bg-primary/5 ring-1 ring-primary",
                          )}
                        >
                          {selected && (
                            <CheckIcon className="absolute top-2 right-2 size-4 text-primary" />
                          )}
                          <div className="flex items-center gap-1.5">
                            <span className={cn("size-1.5 shrink-0 rounded-full", dot)} />
                            <span className="truncate text-sm font-medium">{p.name}</span>
                            <span className="ml-auto shrink-0 text-muted-foreground text-[10px]">
                              {FORMAT_LABELS[p.format]}
                            </span>
                          </div>
                          {p.base_url && (
                            <p className="mt-1 truncate font-mono text-muted-foreground text-[11px]">{p.base_url}</p>
                          )}
                          <p className="mt-1 line-clamp-2 text-muted-foreground text-xs">{p.note}</p>
                          {p.models.length > 0 && (
                            <p className="mt-1.5 text-muted-foreground/80 text-[10px]">
                              {p.models.length} 个常用模型 · {p.models[0].context_k}K 窗口
                            </p>
                          )}
                        </button>
                      );
                    })}
                    {filteredPresets.length === 0 && (
                      <p className="text-muted-foreground col-span-full py-6 text-center text-sm">
                        没有匹配的预设；可下拉到「自定义中转站」手动填写。
                      </p>
                    )}
                  </div>
                </>
              )}

              {step === 2 && (
                <>
                  {activePreset && (
                    <div className="rounded-lg border bg-muted/30 px-3 py-2 text-sm">
                      <span className="font-medium">{activePreset.name}</span>
                      <span className="ml-2 text-muted-foreground text-xs">{FORMAT_LABELS[activePreset.format]}</span>
                      <button
                        type="button"
                        className="ml-2 text-primary text-xs underline"
                        onClick={() => setStep(1)}
                      >
                        更换
                      </button>
                    </div>
                  )}
                  {nameField}
                  {keyField}
                  {(presetId === "custom-relay" || !activePreset?.base_url) && baseUrlField}
                  {proxyField}
                </>
              )}

              {step === 3 && (
                <>
                  {modelField}
                  {cwField}
                  {advancedSection}
                </>
              )}
            </>
          ) : (
            <>
              {/* 编辑模式：核心区 + 高级折叠 */}
              {nameField}
              {modelField}
              {cwField}
              {baseUrlField}
              {keyField}
              {proxyField}
              {advancedSection}
            </>
          )}
        </div>

        {/* 底部操作条 */}
        <div className="flex items-center gap-2 border-t px-4 py-3">
          {isNew ? (
            <>
              {step > 1 && (
                <Button variant="outline" size="sm" onClick={() => setStep(step - 1)} disabled={saving}>
                  <ArrowLeftIcon /> 上一步
                </Button>
              )}
              <div className="ml-auto flex items-center gap-2">
                {step < 3 ? (
                  <Button
                    size="sm"
                    onClick={() => {
                      if (step === 1 && !presetId) {
                        toast.error("先选择一个厂商预设");
                        return;
                      }
                      if (step === 2) {
                        if (!name.trim()) {
                          toast.error("先填写名称");
                          return;
                        }
                        if (!apiKey.trim() && !keyHint) {
                          toast.error("先粘贴 API Key（没有 Key 的配置无法调用）");
                          return;
                        }
                        if (presetId === "custom-relay" && !baseUrl.trim()) {
                          toast.error("自定义中转站需要填写 Base URL");
                          return;
                        }
                      }
                      setStep(step + 1);
                    }}
                  >
                    下一步 <ArrowRightIcon />
                  </Button>
                ) : (
                  <>
                    <Button variant="outline" size="sm" onClick={() => void save(false)} disabled={saving}>
                      <SaveIcon /> 仅保存
                    </Button>
                    <Button size="sm" onClick={() => void save(saveAndActivate)} disabled={saving}>
                      {saving ? <Loader2Icon className="animate-spin" /> : <ZapIcon />} 保存{saveAndActivate ? "并激活" : ""}
                    </Button>
                  </>
                )}
              </div>
            </>
          ) : (
            <>
              <Button variant="outline" size="sm" onClick={() => void testConnection()} disabled={testing}>
                {testing ? <Loader2Icon className="animate-spin" /> : <PlugZapIcon />} 测试连接
              </Button>
              <Button className="ml-auto" size="sm" onClick={() => void save(false)} disabled={saving}>
                {saving ? <Loader2Icon className="animate-spin" /> : <SaveIcon />} 保存
              </Button>
            </>
          )}
        </div>

        {/* 新建第 3 步的保存并激活开关 */}
        {isNew && step === 3 && (
          <div className="flex items-center gap-2 border-t px-4 py-2 text-sm">
            <Switch checked={saveAndActivate} onCheckedChange={setSaveAndActivate} id="save-activate" />
            <Label htmlFor="save-activate" className="cursor-pointer text-muted-foreground">
              保存后设为激活配置（现有任务不受影响，下一轮开始使用）
            </Label>
          </div>
        )}

        {/* 草稿关闭确认 */}
        <AlertDialog open={confirmClose} onOpenChange={setConfirmClose}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>放弃未保存的更改？</AlertDialogTitle>
              <AlertDialogDescription>抽屉里有尚未保存的修改，关闭后这些输入会丢失。</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>继续编辑</AlertDialogCancel>
              <AlertDialogAction
                className="bg-destructive text-white hover:bg-destructive/90"
                onClick={() => {
                  setConfirmClose(false);
                  onOpenChange(false);
                }}
              >
                放弃更改
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </SheetContent>
    </Sheet>
  );
}

