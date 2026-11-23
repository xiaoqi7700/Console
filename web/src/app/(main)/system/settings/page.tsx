"use client";

import * as React from "react";

import { CpuIcon, DatabaseIcon, FlaskConicalIcon, GaugeIcon, KeyboardIcon, RadioTowerIcon, SearchIcon, ShieldAlertIcon, TimerResetIcon } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import { CHAT_SEND_MODE_OPTIONS, type ChatSendMode, setChatSendMode, useChatSendMode } from "@/lib/chat-send-mode";
import type { Settings } from "@/lib/types";

import { UpdateCard } from "./_components/update-card";

export default function SystemSettingsPage() {
  const [trafficCapture, setTrafficCapture] = React.useState(false);
  const [agentTrafficBinding, setAgentTrafficBinding] = React.useState(false);
  const [webSearch, setWebSearch] = React.useState(false);
  const [backend, setBackend] = React.useState("ddgs");
  const [braveKeySet, setBraveKeySet] = React.useState(false);
  const [braveKeyInput, setBraveKeyInput] = React.useState("");
  const [tavilyKeySet, setTavilyKeySet] = React.useState(false);
  const [tavilyKeyInput, setTavilyKeyInput] = React.useState("");
  const [savingTavilyKey, setSavingTavilyKey] = React.useState(false);
  const [proxyInput, setProxyInput] = React.useState("");
  const [savingProxy, setSavingProxy] = React.useState(false);
  const [globalProxyInput, setGlobalProxyInput] = React.useState("");
  const [savedGlobalProxy, setSavedGlobalProxy] = React.useState(""); // #33：状态提示跟已保存值，不跟草稿
  const [artMaxCount, setArtMaxCount] = React.useState("");
  const [artMaxBytes, setArtMaxBytes] = React.useState("");
  const [savingArtifactQuota, setSavingArtifactQuota] = React.useState(false);
  const [savingGlobalProxy, setSavingGlobalProxy] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  // 诊断包导出
  const [diagDetail, setDiagDetail] = React.useState(false);
  const [exportingDiag, setExportingDiag] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [savingKey, setSavingKey] = React.useState(false);
  const [pyInterp, setPyInterp] = React.useState("");
  const [workers, setWorkers] = React.useState("3");
  const [savingWorkers, setSavingWorkers] = React.useState(false);
  // 任务自动收尾（v0.5.0）。
  const [autoFinishEnabled, setAutoFinishEnabled] = React.useState(true);
  const [autoFinishIdle, setAutoFinishIdle] = React.useState("3");
  const [autoFinishMin, setAutoFinishMin] = React.useState("5");
  const [autoFinishCoverage, setAutoFinishCoverage] = React.useState("0");
  const [autoFinishMax, setAutoFinishMax] = React.useState("80");
  const [intentBudgetEnabled, setIntentBudgetEnabled] = React.useState(true);
  const [intentBudgetTokens, setIntentBudgetTokens] = React.useState("3000000");
  const [intentBudgetMinutes, setIntentBudgetMinutes] = React.useState("0");
  const [intentBudgetMode, setIntentBudgetMode] = React.useState("soft");
  const [savingIntentBudget, setSavingIntentBudget] = React.useState(false);
  const [savingAutoFinish, setSavingAutoFinish] = React.useState(false);
  // 冷节点压缩的输出预算与墙钟上限。0=用默认值(65536 token / 20 分钟)。
  const [compactionTokens, setCompactionTokens] = React.useState("0");
  const [compactionTimeout, setCompactionTimeout] = React.useState("0");
  const [compactionMembers, setCompactionMembers] = React.useState("0");
  const [savingCompaction, setSavingCompaction] = React.useState(false);
  // B10:压缩器钉住的 LLM 配置。"0"=跟随规划器(历史行为)。选项来自 LLM 配置列表,
  // 加载失败时不挡页面,只显示「跟随规划器」一项。
  const [compactorProfile, setCompactorProfile] = React.useState("0");
  const [llmProfileOpts, setLlmProfileOpts] = React.useState<{ id: string; name: string }[]>([]);
  // 操作约束注入范围(默认都开)。
  const [injectPlanner, setInjectPlanner] = React.useState(true);
  const [injectWorker, setInjectWorker] = React.useState(true);
  // 实验功能:noa 上下文压缩(默认关)。
  const [noaCompaction, setNoaCompaction] = React.useState(false);
  // 纯前端偏好：不走 /api/settings，直接读写 localStorage。
  const sendMode = useChatSendMode();

  const apply = React.useCallback((s: Settings) => {
    setTrafficCapture(!!s.traffic_capture);
    setAgentTrafficBinding(!!s.agent_traffic_binding);
    setWebSearch(!!s.web_search_enabled);
    setBackend(s.web_search_backend || "ddgs");
    setBraveKeySet(!!s.brave_key_set);
    setTavilyKeySet(!!s.tavily_key_set);
    setProxyInput(s.web_search_proxy ?? "");
    setGlobalProxyInput(s.global_proxy ?? "");
    setSavedGlobalProxy(s.global_proxy ?? "");
    setArtMaxCount(String(s.artifact_max_count ?? ""));
    setArtMaxBytes(String(Math.round((s.artifact_max_bytes ?? 0) / (1024 * 1024)) || ""));
    setPyInterp(s.python_interpreter ?? "");
    setWorkers(String(s.workers ?? 3));
    setCompactionTokens(String(s.compaction_max_tokens ?? 0));
    setCompactionTimeout(String(s.compaction_timeout_seconds ?? 0));
    setCompactionMembers(String(s.compaction_max_members ?? 0));
    setCompactorProfile(String(s.compactor_profile_id ?? 0));
    setInjectPlanner(s.constraints_inject_planner !== false);
    setInjectWorker(s.constraints_inject_worker !== false);
    setNoaCompaction(!!s.noa_compaction);
    setAutoFinishEnabled(s.auto_finish_enabled !== false);
    setAutoFinishIdle(String(s.auto_finish_idle_rounds ?? 3));
    setAutoFinishMin(String(s.auto_finish_min_rounds ?? 5));
    setAutoFinishCoverage(String(s.auto_finish_coverage_pct ?? 0));
    setAutoFinishMax(String(s.auto_finish_max_rounds ?? 80));
    setIntentBudgetEnabled(s.intent_budget_enabled !== false);
    setIntentBudgetTokens(String(s.intent_budget_tokens ?? 3000000));
    setIntentBudgetMinutes(String(s.intent_budget_minutes ?? 0));
    setIntentBudgetMode(s.intent_budget_mode === "hard" ? "hard" : "soft");
  }, []);

  const saveWorkers = () => {
    const n = Number(workers);
    if (!Number.isInteger(n) || n <= 0) {
      toast.error("并发数必须是大于 0 的整数");
      return;
    }
    setSavingWorkers(true);
    api
      .setSettings({ workers: n })
      .then((s) => {
        apply(s);
        toast.success("已保存并发工作 agent 数（对之后启动的任务生效）");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingWorkers(false));
  };

  const saveAutoFinish = () => {
    const idle = Number(autoFinishIdle);
    const min = Number(autoFinishMin);
    const cov = Number(autoFinishCoverage);
    const max = Number(autoFinishMax);
    if (!Number.isInteger(idle) || idle < 2 || idle > 20) {
      toast.error("连续无新增轮数必须在 2–20 之间");
      return;
    }
    if (!Number.isInteger(min) || min < 1 || min > 50) {
      toast.error("最少规划轮数必须在 1–50 之间");
      return;
    }
    if (!Number.isInteger(cov) || cov < 0 || cov > 100) {
      toast.error("覆盖率阈值必须在 0–100 之间（0 = 关闭）");
      return;
    }
    if (!Number.isInteger(max) || max < 0 || max > 500) {
      toast.error("最大规划轮数必须在 0–500 之间（0 = 不限）");
      return;
    }
    setSavingAutoFinish(true);
    api
      .setSettings({
        auto_finish_enabled: autoFinishEnabled,
        auto_finish_idle_rounds: idle,
        auto_finish_min_rounds: min,
        auto_finish_coverage_pct: cov,
        auto_finish_max_rounds: max,
      })
      .then((s) => {
        apply(s);
        toast.success("已保存自动收尾设置（下一轮规划生效）");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingAutoFinish(false));
  };

  const saveIntentBudget = () => {
    const tokens = Number(intentBudgetTokens);
    if (!Number.isInteger(tokens) || tokens < 500000 || tokens > 20000000) {
      toast.error("意图 token 预算必须在 500000–20000000 之间");
      return;
    }
    const mins = Number(intentBudgetMinutes);
    if (!Number.isInteger(mins) || mins < 0 || mins > 240) {
      toast.error("墙钟预算必须在 0–240 分钟（0=关）");
      return;
    }
    if (intentBudgetMode !== "soft" && intentBudgetMode !== "hard") {
      toast.error("预算模式仅支持 soft / hard");
      return;
    }
    setSavingIntentBudget(true);
    api
      .setSettings({
        intent_budget_enabled: intentBudgetEnabled,
        intent_budget_tokens: tokens,
        intent_budget_minutes: mins,
        intent_budget_mode: intentBudgetMode,
      })
      .then((s) => {
        apply(s);
        toast.success("已保存意图预算（对之后启动的意图生效）");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingIntentBudget(false));
  };

  const saveCompaction = () => {
    const t = Number(compactionTokens);
    const to = Number(compactionTimeout);
    const m = Number(compactionMembers);
    if (!Number.isInteger(t) || t < 0) {
      toast.error("输出预算必须是不小于 0 的整数（0 = 默认）");
      return;
    }
    if (!Number.isInteger(to) || to < 0) {
      toast.error("超时必须是不小于 0 的整数秒（0 = 默认）");
      return;
    }
    if (!Number.isInteger(m) || m < 0) {
      toast.error("单块节点数必须是不小于 0 的整数（0 = 默认）");
      return;
    }
    setSavingCompaction(true);
    api
      .setSettings({
        compaction_max_tokens: t,
        compaction_timeout_seconds: to,
        compaction_max_members: m,
      })
      .then((s) => {
        apply(s);
        toast.success("已保存压缩参数（对之后启动的任务生效）");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingCompaction(false));
  };

  const savePython = () => {    setSaving(true);
    api
      .setSettings({ python_interpreter: pyInterp.trim() })
      .then((s) => {
        apply(s);
        toast.success("已保存 Python 解释器配置");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSaving(false));
  };
  const detectPython = () => {
    setSaving(true);
    api
      .detectPython()
      .then((r) => setPyInterp(r.python_interpreter))
      .catch(() => undefined)
      .finally(() => setSaving(false));
  };

  React.useEffect(() => {
    api
      .settings()
      .then(apply)
      .catch(() => undefined)
      .finally(() => setLoaded(true));
    // B10:压缩器模型下拉需要配置列表。best-effort——失败只是少几个选项。
    api
      .llmProfiles()
      .then((ps) => setLlmProfileOpts(ps.map((p) => ({ id: p.id, name: p.name }))))
      .catch(() => setLlmProfileOpts([]));
  }, [apply]);

  const toggleTraffic = (v: boolean) => {
    setTrafficCapture(v); // optimistic
    setSaving(true);
    api
      .setSettings({ traffic_capture: v })
      .then(apply)
      .catch(() => setTrafficCapture(!v)) // revert on failure
      .finally(() => setSaving(false));
  };

  const toggleInjectPlanner = (v: boolean) => {
    setInjectPlanner(v); // optimistic
    api
      .setSettings({ constraints_inject_planner: v })
      .then(apply)
      .catch(() => setInjectPlanner(!v)); // revert on failure
  };

  const toggleAgentTrafficBinding = (v: boolean) => {
    setAgentTrafficBinding(v);
    setSaving(true);
    api
      .setSettings({ agent_traffic_binding: v })
      .then((s) => {
        apply(s);
        toast.success(v ? "已开启 Agent 自动绑定流量" : "已关闭 Agent 自动绑定流量");
      })
      .catch((e) => {
        setAgentTrafficBinding(!v);
        toast.error(`保存失败：${(e as Error).message}`);
      })
      .finally(() => setSaving(false));
  };

  const toggleInjectWorker = (v: boolean) => {
    setInjectWorker(v); // optimistic
    api
      .setSettings({ constraints_inject_worker: v })
      .then(apply)
      .catch(() => setInjectWorker(!v)); // revert on failure
  };

  const toggleNoaCompaction = (v: boolean) => {
    setNoaCompaction(v); // optimistic
    api
      .setSettings({ noa_compaction: v })
      .then((s) => {
        apply(s);
        toast.success(v ? "已开启 noa 上下文压缩（对之后启动的运行生效）" : "已关闭 noa 上下文压缩（恢复内置压缩）");
      })
      .catch((e) => {
        setNoaCompaction(!v); // revert on failure
        toast.error(`保存失败：${(e as Error).message}`);
      });
  };

  // B10:压缩器钉住的配置，onValueChange 即存（乐观更新）。对之后启动的任务与
  // 运行中任务的下一轮生效——后端会在保存时重建任务 agent 集合。
  const saveCompactorProfile = (v: string) => {
    const prev = compactorProfile;
    setCompactorProfile(v);
    api
      .setSettings({ compactor_profile_id: Number(v) })
      .then((s) => {
        apply(s);
        toast.success(Number(v) > 0 ? "已保存压缩器模型（对之后启动的任务生效）" : "已恢复压缩器跟随规划器");
      })
      .catch((e) => {
        setCompactorProfile(prev); // revert on failure
        toast.error(`保存失败：${(e as Error).message}`);
      });
  };

  // Persist a web-search patch (enable and/or backend). Optimistic with refetch.
  const saveWebSearch = (patch: Partial<Settings>) => {
    setSaving(true);
    api
      .setSettings(patch)
      .then((s) => {
        apply(s);
        toast.success("已保存网络搜索配置");
      })
      .catch((e) => {
        toast.error(`保存失败：${(e as Error).message}`);
        api
          .settings()
          .then(apply)
          .catch(() => undefined);
      })
      .finally(() => setSaving(false));
  };

  const saveBraveKey = () => {
    setSavingKey(true);
    api
      .setSettings({ brave_search_api_key: braveKeyInput })
      .then((s) => {
        apply(s);
        setBraveKeyInput("");
        toast.success("已保存 Brave API Key");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingKey(false));
  };

  const saveTavilyKey = () => {
    setSavingTavilyKey(true);
    api
      .setSettings({ tavily_search_api_key: tavilyKeyInput })
      .then((s) => {
        apply(s);
        setTavilyKeyInput("");
        toast.success("已保存 Tavily API Key");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingTavilyKey(false));
  };

  const saveProxy = () => {
    setSavingProxy(true);
    api
      .setSettings({ web_search_proxy: proxyInput.trim() })
      .then((s) => {
        apply(s);
        toast.success(proxyInput.trim() ? "已保存出口代理" : "已清除出口代理（改为直连）");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingProxy(false));
  };

  const saveGlobalProxy = () => {
    setSavingGlobalProxy(true);
    api
      .setSettings({ global_proxy: globalProxyInput.trim() })
      .then((s) => {
        apply(s);
        toast.success(globalProxyInput.trim() ? "已保存全局代理" : "已清除全局代理（改为直连）");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingGlobalProxy(false));
  };

  // #45/#50：证据附件限额（空值=恢复默认 300 件 / 500MB）。
  const saveArtifactQuota = () => {
    const cnt = parseInt(artMaxCount, 10);
    const mb = parseInt(artMaxBytes, 10);
    setSavingArtifactQuota(true);
    api
      .setSettings({
        artifact_max_count: Number.isFinite(cnt) && cnt > 0 ? cnt : 0,
        artifact_max_bytes: Number.isFinite(mb) && mb > 0 ? mb * 1024 * 1024 : 0,
      })
      .then((st) => {
        apply(st);
        toast.success("已保存证据附件限额");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingArtifactQuota(false));
  };


  // Run a real "test" search ("test") against the CURRENT form values (backend +
  // proxy + entered key), falling back to saved values server-side. Toasts result.
  const runTest = () => {
    setTesting(true);
    api
      .testWebSearch({
        web_search_backend: backend,
        web_search_proxy: proxyInput.trim(),
        brave_search_api_key: braveKeyInput,
        tavily_search_api_key: tavilyKeyInput,
      })
      .then((r) => {
        if (r.ok) toast.success(`搜索测试成功 · ${r.backend} 返回 ${r.count} 条结果`);
        else toast.error(`搜索测试失败：${r.error || "未知错误"}`);
      })
      .catch((e) => toast.error(`搜索测试失败：${(e as Error).message}`))
      .finally(() => setTesting(false));
  };

  // brave-free selected but no key stored and none being entered → tool stays off.
  const braveNeedsKey = webSearch && backend === "brave-free" && !braveKeySet;

  async function exportDiagnostics() {
    if (exportingDiag) return;
    setExportingDiag(true);
    try {
      await api.exportDiagnostics({ detail: diagDetail });
      toast.success("诊断包已开始下载");
    } catch (e) {
      toast.error(`导出失败：${(e as Error).message}`);
    } finally {
      setExportingDiag(false);
    }
  }

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <PageHeader
        title="系统配置"
        description="全局运行时开关：更新、执行并发、自主推进边界、网络与流量、模型上下文与维护。任务级覆盖在任务详情中设置。"
      />

      {/* 两列网格 + 分区标题（参考内部版）：卡片按语义分组、同行等高；
          分区标题本身是 col-span-2 的网格项，因此总在新区块行首。 */}
      <div className="grid grid-cols-1 items-stretch gap-4 md:gap-6 lg:grid-cols-2 [&_[data-slot=card]]:h-full [&_[data-slot=card-content]]:flex-1">
        <div className="order-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground lg:col-span-2">版本更新</div>
        <div className="order-2 lg:col-span-2 [&_[data-slot=card]]:h-full">
          <UpdateCard />
        </div>
        <div className="order-12 text-xs font-semibold uppercase tracking-wider text-muted-foreground lg:col-span-2">网络与流量</div>
        <div className="order-20 text-xs font-semibold uppercase tracking-wider text-muted-foreground lg:col-span-2">执行与并发</div>
        <div className="order-30 text-xs font-semibold uppercase tracking-wider text-muted-foreground lg:col-span-2">模型与上下文</div>
        <div className="order-40 text-xs font-semibold uppercase tracking-wider text-muted-foreground lg:col-span-2">功能与偏好</div>
        <div className="order-50 text-xs font-semibold uppercase tracking-wider text-muted-foreground lg:col-span-2">系统维护</div>

        <Card className="order-13">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <RadioTowerIcon className="size-4" />
              流量捕获
            </CardTitle>
            <CardDescription>
              开启后，所有 Agent 的 HTTP 流量经记录代理全量落库，并向 Agent 注入 traffic_search / traffic_get
              工具与代理配置（提示词含代理说明）。
              <br />
              关闭（默认）时不记录任何流量：Agent
              <b>不会</b>拿到代理配置与流量工具，提示词也<b>不含</b>代理相关内容。切换后会即时重建 Agent 生效。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between gap-4">
            <Label htmlFor="traffic-capture" className="font-normal text-muted-foreground text-sm">
              {trafficCapture ? "已开启 · 正在记录流量并注入代理" : "已关闭 · 不记录、不注入代理"}
            </Label>
            <Switch
              id="traffic-capture"
              checked={trafficCapture}
              disabled={!loaded || saving}
              onCheckedChange={toggleTraffic}
            />
          </CardContent>
        </Card>

        <Card className="order-14">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <RadioTowerIcon className="size-4" />
              Agent 自动绑定流量
            </CardTitle>
            <CardDescription id="agent-traffic-binding-description">
              默认关闭。开启后，漏洞入库时触发的报告 Agent 会核对已有 HTTP 请求/响应，关联对应流量后再编写报告。
              <b>查阅数据包及额外的工具调用会增加 Token 消耗。</b>
              <br />
              TCP、未抓包或没有匹配流量时仍可正常上报。此开关不影响流量捕获、人工绑定及已保存证据的查看。 对下一轮 Agent
              生效；关闭后会立即拒绝新的自动绑定。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between gap-4">
            <Label htmlFor="agent-traffic-binding" className="font-normal text-muted-foreground text-sm">
              {agentTrafficBinding ? "已开启 · 会增加 Token 消耗" : "已关闭 · 可继续人工绑定"}
            </Label>
            <Switch
              id="agent-traffic-binding"
              aria-describedby="agent-traffic-binding-description"
              checked={agentTrafficBinding}
              disabled={!loaded || saving}
              onCheckedChange={toggleAgentTrafficBinding}
            />
          </CardContent>
        </Card>

        <Card className="order-15">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <RadioTowerIcon className="size-4" />
              全局代理
            </CardTitle>
            <CardDescription>
              所有 Agent 的<b>目标流量</b>经此代理出网（隐藏源 IP / 走跳板）。支持 <b>http / https / socks5</b>，可带{" "}
              <code>user:pass</code> 认证。留空=直连。
              <br />
              开启<b>流量捕获</b>时，它作为记录代理的<b>上游</b>（流量仍全量落库，再经此代理出网）；关闭捕获时，直接注入
              Agent 的 bash / WebFetch 出网。与网络搜索代理、LLM 代理相互独立。
              检查和下载程序更新优先使用宿主环境中的「装机代理」，未配置时才使用全局代理。
              <br />
              <b>提示</b>：socks5 在<b>关闭捕获</b>时依赖各命令行工具对 <code>ALL_PROXY</code> 的支持（curl
              可用，部分工具可能忽略）； 若主要用 socks5，建议开启流量捕获——此路径由 MITM
              亲自拨号，工具无感知、稳定生效。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            <Label htmlFor="global-proxy" className="font-normal text-muted-foreground text-sm">
              代理地址
            </Label>
            <div className="flex items-center gap-2">
              <Input
                id="global-proxy"
                autoComplete="off"
                placeholder="socks5://user:pass@host:1080 或 http://host:port（留空=直连）"
                value={globalProxyInput}
                disabled={!loaded || savingGlobalProxy}
                onChange={(e) => setGlobalProxyInput(e.target.value)}
              />
              <Button type="button" onClick={saveGlobalProxy} disabled={!loaded || savingGlobalProxy}>
                保存
              </Button>
            </div>
            <p className="text-muted-foreground text-xs">
              {savedGlobalProxy.trim() ? "已配置 · 所有目标流量经此代理出网" : "未配置 · 目标流量直连出网"}
              {globalProxyInput.trim() !== savedGlobalProxy.trim() && (
                <span className="ml-2 rounded bg-amber-500/15 px-1.5 py-0.5 text-amber-600 dark:text-amber-400">
                  有未保存的更改 · 保存后生效
                </span>
              )}
            </p>
          </CardContent>
        </Card>

        <Card className="order-15">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <DatabaseIcon className="size-4" />
              证据附件限额
            </CardTitle>
            <CardDescription>
              每个任务的证据附件件数与总量上限（#45/#50）。留空/0 = 恢复默认（300 件 / 500MB）。长任务触顶后
              <code>save_evidence</code> 会失败，可在任务页删除旧附件释放配额，或在这里调高。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <Input
                className="w-40"
                inputMode="numeric"
                placeholder="件数（默认 300）"
                value={artMaxCount}
                disabled={!loaded || savingArtifactQuota}
                onChange={(e) => setArtMaxCount(e.target.value.replace(/[^0-9]/g, ""))}
              />
              <Input
                className="w-44"
                inputMode="numeric"
                placeholder="总量 MB（默认 500）"
                value={artMaxBytes}
                disabled={!loaded || savingArtifactQuota}
                onChange={(e) => setArtMaxBytes(e.target.value.replace(/[^0-9]/g, ""))}
              />
              <Button type="button" onClick={saveArtifactQuota} disabled={!loaded || savingArtifactQuota}>
                保存
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="order-21">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldAlertIcon className="size-4" />
              操作约束注入
            </CardTitle>
            <CardDescription>
              开启后，把每个任务的<b>操作约束</b>（在任务总览「操作约束」里维护的 allow/deny 条目）拼进对应 Agent
              的系统提示，用来框定探索边界（如「仅测当前端口」「禁止爆破」）。
              <br />
              可分别控制注入到 <b>规划者（planner）</b>与 <b>执行者（worker）</b>
              ；默认都开。切换即时生效（下一轮读取），无需重建 Agent。关闭后该 Agent 不再看到约束。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="inject-planner" className="font-normal text-muted-foreground text-sm">
                注入规划者（planner）{injectPlanner ? " · 已开启" : " · 已关闭"}
              </Label>
              <Switch
                id="inject-planner"
                checked={injectPlanner}
                disabled={!loaded}
                onCheckedChange={toggleInjectPlanner}
              />
            </div>
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="inject-worker" className="font-normal text-muted-foreground text-sm">
                注入执行者（worker）{injectWorker ? " · 已开启" : " · 已关闭"}
              </Label>
              <Switch
                id="inject-worker"
                checked={injectWorker}
                disabled={!loaded}
                onCheckedChange={toggleInjectWorker}
              />
            </div>
          </CardContent>
        </Card>

        <Card className="order-31">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <FlaskConicalIcon className="size-4" />
              实验功能
            </CardTitle>
            <CardDescription>
              尚在验证中的机制，默认关闭。可能改变 Agent 行为或影响稳定性，请在了解影响后启用。
              <br />
              <b>noa 上下文压缩</b>：由模型主动压缩长对话历史（norma v0.4.0）。开启后平台接入的四类 Agent（
              <b>规划者 / 执行者 / 主 Agent / 对话</b>）改用 noa 接管上下文，取代内置压缩，
              压缩原文会归档到任务工作目录下便于回溯。切换即时生效（对之后启动的运行生效），无需重建 Agent；
              关闭后立即恢复内置压缩。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between gap-4">
            <Label htmlFor="noa-compaction" className="font-normal text-muted-foreground text-sm">
              noa 上下文压缩{noaCompaction ? " · 已开启" : " · 已关闭"}
            </Label>
            <Switch
              id="noa-compaction"
              checked={noaCompaction}
              disabled={!loaded}
              onCheckedChange={toggleNoaCompaction}
            />
          </CardContent>
        </Card>

        <Card className="order-41">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <SearchIcon className="size-4" />
              网络搜索
            </CardTitle>
            <CardDescription>
              这是网络搜索的<b>总开关 + 来源配置</b>。开启后，才能在<b>每个 Agent 的配置</b>里单独选择是否启用
              <b>web_search</b>（仅返回标题/链接/摘要，不抓取正文；抓取由 WebFetch 负责）。网络搜索<b>不走</b>
              记录代理，独立于流量捕获。
              <br />
              来源可选 <b>DuckDuckGo（ddgs）</b>（无需 Key）、<b>Brave（免费版）</b>（需填写 Brave API Key）、{" "}
              <b>Tavily</b>（需填写 Tavily API Key）或 <b>DeepSeek</b>（复用当前 LLM 配置）。总开关关闭时，各
              Agent 的网络搜索开关不可用。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="web-search" className="font-normal text-muted-foreground text-sm">
                {webSearch ? "总开关已开启 · 可在各 Agent 配置里单独启用" : "已关闭 · 各 Agent 无法启用网络搜索"}
              </Label>
              <Switch
                id="web-search"
                checked={webSearch}
                disabled={!loaded || saving}
                onCheckedChange={(v) => {
                  setWebSearch(v); // optimistic
                  saveWebSearch({ web_search_enabled: v });
                }}
              />
            </div>

            {webSearch && (
              <div className="flex items-center justify-between gap-4">
                <Label className="font-normal text-muted-foreground text-sm">搜索来源</Label>
                <Select
                  value={backend}
                  disabled={!loaded || saving}
                  onValueChange={(v) => {
                    setBackend(v); // optimistic
                    saveWebSearch({ web_search_backend: v });
                  }}
                >
                  <SelectTrigger className="w-48 shrink-0">
                    <SelectValue placeholder="选择来源" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ddgs">DuckDuckGo（ddgs · 免费无 Key）</SelectItem>
                    <SelectItem value="brave-free">Brave（免费版 · 需 Key）</SelectItem>
                    <SelectItem value="tavily">Tavily（需 Key）</SelectItem>
                    <SelectItem value="deepseek">DeepSeek（官方）</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}

            {webSearch && backend === "deepseek" && (
              <div className="flex flex-col gap-2 rounded-md border border-border/60 bg-muted/30 p-3">
                <p className="font-medium text-sm">DeepSeek 官方联网搜索</p>
                <p className="text-muted-foreground text-xs leading-relaxed">
                  该来源直接复用<b>当前激活的 LLM 配置</b>。因此它
                  <b>仅支持 DeepSeek 官方模型</b>，且该配置<b>必须使用 anthropic 协议</b>
                  ——DeepSeek 的 OpenAI 协议端点不支持服务端搜索。切换 LLM 配置后此来源可能失效。
                </p>
                <p className="text-muted-foreground text-xs leading-relaxed">
                  与其它来源不同，搜索由 <b>DeepSeek 服务端执行</b>：每次搜索会额外消耗一次模型调用（产生 Token
                  费用），搜索请求<b>不经过上面的出口代理</b>，也<b>不计入流量留痕</b>；返回结果<b>只有标题和链接</b>
                  （无摘要），需要正文时由 WebFetch 抓取。
                </p>
                <p className="text-muted-foreground text-xs leading-relaxed">
                  是否满足上述条件由你自行确认，系统不做拦截；可用下方「测试搜索」按钮实际跑一次来验证。
                </p>
              </div>
            )}

            {webSearch && backend === "brave-free" && (
              <div className="flex flex-col gap-2">
                <Label htmlFor="brave-key" className="font-normal text-muted-foreground text-sm">
                  Brave Search API Key
                  {braveKeySet && <span className="ml-2 text-emerald-500 text-xs">已配置</span>}
                </Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="brave-key"
                    type="password"
                    autoComplete="off"
                    placeholder={braveKeySet ? "已配置（留空则不变）" : "输入 Brave API Key"}
                    value={braveKeyInput}
                    disabled={!loaded || savingKey}
                    onChange={(e) => setBraveKeyInput(e.target.value)}
                  />
                  <Button
                    type="button"
                    onClick={saveBraveKey}
                    disabled={!loaded || savingKey || braveKeyInput.trim() === ""}
                  >
                    保存
                  </Button>
                </div>
                {braveNeedsKey && (
                  <p className="text-amber-500 text-xs">
                    已选择 Brave 但尚未配置 Key —— 在保存 Key 之前，搜索工具不会启用。
                  </p>
                )}
                <p className="text-muted-foreground text-xs">
                  免费版额度约 2,000 次/月。前往 https://brave.com/search/api/ 获取 Key。
                </p>
              </div>
            )}

            {webSearch && backend === "tavily" && (
              <div className="flex flex-col gap-2">
                <Label htmlFor="tavily-key" className="font-normal text-muted-foreground text-sm">
                  Tavily Search API Key
                  {tavilyKeySet && <span className="ml-2 text-emerald-500 text-xs">已配置</span>}
                </Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="tavily-key"
                    type="password"
                    autoComplete="off"
                    placeholder={tavilyKeySet ? "已配置（留空则不变）" : "输入 Tavily API Key（tvly-…）"}
                    value={tavilyKeyInput}
                    disabled={!loaded || savingTavilyKey}
                    onChange={(e) => setTavilyKeyInput(e.target.value)}
                  />
                  <Button
                    type="button"
                    onClick={saveTavilyKey}
                    disabled={!loaded || savingTavilyKey || tavilyKeyInput.trim() === ""}
                  >
                    保存
                  </Button>
                </div>
                {webSearch && backend === "tavily" && !tavilyKeySet && (
                  <p className="text-amber-500 text-xs">
                    已选择 Tavily 但尚未配置 Key —— 在保存 Key 之前，搜索工具不会启用。
                  </p>
                )}
                <p className="text-muted-foreground text-xs">前往 https://tavily.com 注册并获取 API Key。</p>
              </div>
            )}

            {webSearch && (
              <div className="flex flex-col gap-2">
                <Label htmlFor="ws-proxy" className="font-normal text-muted-foreground text-sm">
                  出口代理（可选）
                </Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="ws-proxy"
                    autoComplete="off"
                    placeholder="http://host:port 或 socks5://host:port（留空=直连）"
                    value={proxyInput}
                    disabled={!loaded || savingProxy}
                    onChange={(e) => setProxyInput(e.target.value)}
                  />
                  <Button type="button" onClick={saveProxy} disabled={!loaded || savingProxy}>
                    保存
                  </Button>
                </div>
                <p className="text-muted-foreground text-xs">
                  独立出口代理，仅用于访问搜索端点（VPN/SOCKS 等）。与记录流量的 MITM 代理无关；网络不通时经此代理访问。
                </p>
              </div>
            )}

            {webSearch && (
              <div className="flex items-center justify-between gap-4 border-t pt-4">
                <p className="text-muted-foreground text-xs">
                  用当前配置（来源 + 代理 + Key）实际搜索一次「test」，验证是否可用。
                </p>
                <Button
                  type="button"
                  variant="outline"
                  onClick={runTest}
                  disabled={!loaded || testing}
                  className="shrink-0"
                >
                  {testing ? "测试中…" : "测试搜索"}
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="order-42">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <RadioTowerIcon className="size-4" />
              自定义脚本 · Python 解释器
            </CardTitle>
            <CardDescription>
              自定义 <b>script</b> 类型工具用它跑 Python。开机会自动检测（python3 优先）；此处可手填 venv /
              特定版本的绝对路径，留空则运行时自动检测。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex items-center gap-2">
              <Input
                className="font-mono text-sm"
                placeholder="/usr/bin/python3（留空=自动检测）"
                value={pyInterp}
                disabled={!loaded || saving}
                onChange={(e) => setPyInterp(e.target.value)}
              />
              <Button variant="outline" onClick={detectPython} disabled={!loaded || saving}>
                重新检测
              </Button>
              <Button onClick={savePython} disabled={!loaded || saving}>
                保存
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="order-22">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <CpuIcon className="size-4" />
              工作并发 · Work Agent 数
            </CardTitle>
            <CardDescription>
              每个任务并发运行的工作 agent 数量（默认 3）。数值越大并发探测越多、消耗也越高。修改后
              <b>对之后启动的任务生效</b>，正在运行的任务不受影响。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex items-center gap-2">
              <Input
                type="number"
                min={1}
                className="w-32 font-mono text-sm"
                placeholder="3"
                value={workers}
                disabled={!loaded || savingWorkers}
                onChange={(e) => setWorkers(e.target.value)}
              />
              <Button onClick={saveWorkers} disabled={!loaded || savingWorkers}>
                保存
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="order-23">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <TimerResetIcon className="size-4" />
              任务自动收尾
            </CardTitle>
            <CardDescription>
              跑到该结束就结束：<b>连续 N 轮无新增</b>（facts/findings/已测资产都无增长，且没有在跑意图）、
              <b>覆盖率达标</b>（可关闭）、或达到<b>最大规划轮数</b>时自动收尾。planner 判定目标达成
              （goal_met）且无在跑意图也会直接结束。收尾统一落 <code>done</code>，原因写入活动流；
              暂停/排队中的任务不判定。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-4 rounded-lg border px-3 py-2">
              <div className="flex flex-col">
                <span className="text-sm font-medium">启用自动收尾</span>
                <span className="text-muted-foreground text-xs">关闭后只能靠任务超时或目标闭环结束</span>
              </div>
              <Switch
                checked={autoFinishEnabled}
                disabled={!loaded || savingAutoFinish}
                onCheckedChange={setAutoFinishEnabled}
              />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="flex flex-col gap-1 text-sm">
                <span>连续无新增轮数（2–20）</span>
                <Input
                  type="number"
                  min={2}
                  max={20}
                  className="w-full font-mono text-sm sm:w-40"
                  value={autoFinishIdle}
                  disabled={!loaded || savingAutoFinish}
                  onChange={(e) => setAutoFinishIdle(e.target.value)}
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span>最少规划轮数（1–50）</span>
                <Input
                  type="number"
                  min={1}
                  max={50}
                  className="w-full font-mono text-sm sm:w-40"
                  value={autoFinishMin}
                  disabled={!loaded || savingAutoFinish}
                  onChange={(e) => setAutoFinishMin(e.target.value)}
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span>覆盖率阈值 %（0 = 关闭）</span>
                <Input
                  type="number"
                  min={0}
                  max={100}
                  className="w-full font-mono text-sm sm:w-40"
                  value={autoFinishCoverage}
                  disabled={!loaded || savingAutoFinish}
                  onChange={(e) => setAutoFinishCoverage(e.target.value)}
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span>最大规划轮数（0 = 不限）</span>
                <Input
                  type="number"
                  min={0}
                  max={500}
                  className="w-full font-mono text-sm sm:w-40"
                  value={autoFinishMax}
                  disabled={!loaded || savingAutoFinish}
                  onChange={(e) => setAutoFinishMax(e.target.value)}
                />
              </label>
            </div>
            <div>
              <Button onClick={saveAutoFinish} disabled={!loaded || savingAutoFinish}>
                {savingAutoFinish ? "保存中…" : "保存"}
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="order-24">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <GaugeIcon className="size-4" />
              意图级软预算与重复调用拦截
            </CardTitle>
            <CardDescription>
              单条意图累计 token 到预算后，系统向运行中的 worker 注入一条<b>收尾提醒</b>：
              停止扩大探索、把已有结论写回后结束（软提醒，不杀进程；任务超时与自动收尾仍是最终兜底）。
              默认 300 万——任务 5 实测单意图均值 ≈300 万，超出的意图通常是空转。
              <br />
              重复调用拦截随此开关联动：同一工具+完全相同入参连续 3 次会被拦下并回喂纠正提示
              （同一串最多拦 2 次，之后放行兜底，不会卡死）。修改后<b>对之后启动的意图生效</b>。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-4 rounded-lg border px-3 py-2">
              <div className="flex flex-col">
                <span className="text-sm font-medium">启用意图预算提醒</span>
                <span className="text-muted-foreground text-xs">关闭后不注入提醒，也不做重复调用拦截</span>
              </div>
              <Switch
                checked={intentBudgetEnabled}
                disabled={!loaded || savingIntentBudget}
                onCheckedChange={setIntentBudgetEnabled}
              />
            </div>
            <div className="flex flex-wrap items-end gap-3">
              <label className="flex flex-col gap-1 text-sm">
                <span>单意图 token 预算（500000–20000000）</span>
                <Input
                  type="number"
                  min={500000}
                  max={20000000}
                  step={100000}
                  className="w-full font-mono text-sm sm:w-48"
                  value={intentBudgetTokens}
                  disabled={!loaded || savingIntentBudget}
                  onChange={(e) => setIntentBudgetTokens(e.target.value)}
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span>墙钟预算（分钟，0=关）</span>
                <Input
                  type="number"
                  min={0}
                  max={240}
                  className="w-full font-mono text-sm sm:w-32"
                  value={intentBudgetMinutes}
                  disabled={!loaded || savingIntentBudget}
                  onChange={(e) => setIntentBudgetMinutes(e.target.value)}
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span>超预算模式</span>
                <Select value={intentBudgetMode} onValueChange={setIntentBudgetMode}>
                  <SelectTrigger className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="soft">soft（提醒一次）</SelectItem>
                    <SelectItem value="hard">hard（强制收尾）</SelectItem>
                  </SelectContent>
                </Select>
              </label>
            </div>
            <div>
              <Button onClick={saveIntentBudget} disabled={!loaded || savingIntentBudget}>
                {savingIntentBudget ? "保存中…" : "保存"}
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="order-32">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <CpuIcon className="size-4" />
              上下文压缩参数
            </CardTitle>
            <CardDescription>
              冷节点压缩（把已完成的探索结论压成摘要）是<b>后台</b>跑的，不阻塞 agent 干活，
              等久一点只影响摘要晚点落地。
              <br />
              <b>输出预算</b>是「思考 + 正文」共用的额度：思考型模型（强制 adaptive thinking
              的那些）的思考长度随这个额度线性膨胀，额度给小了它会一直想、正文一个字都吐不出来
              —— 实测 1500 / 2048 / 4096 / 8192 全部得到空正文。默认 65536。
              <br />
              <b>单块节点数上限</b>决定一次请求里塞多少个节点：实测 9 个节点 3 块里仍有 1 块失败，
              6 个节点能稳定收尾。所以超大连通块必须切分。默认 6。
              <br />
              两项填 0 即使用默认值。修改后<b>对之后启动的任务生效</b>。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <Label htmlFor="compaction-tokens" className="w-40 shrink-0 text-sm">
                输出预算 (token)
              </Label>
              <Input
                id="compaction-tokens"
                type="number"
                min={0}
                step={1024}
                className="w-full font-mono text-sm sm:w-40"
                placeholder="0 = 默认 65536"
                value={compactionTokens}
                disabled={!loaded || savingCompaction}
                onChange={(e) => setCompactionTokens(e.target.value)}
              />
              <Label htmlFor="compaction-timeout" className="w-40 shrink-0 text-sm">
                单次超时 (秒)
              </Label>
              <Input
                id="compaction-timeout"
                type="number"
                min={0}
                step={60}
                className="w-full font-mono text-sm sm:w-40"
                placeholder="0 = 默认 1200"
                value={compactionTimeout}
                disabled={!loaded || savingCompaction}
                onChange={(e) => setCompactionTimeout(e.target.value)}
              />
              <Label htmlFor="compaction-members" className="w-40 shrink-0 text-sm">
                单块节点数上限
              </Label>
              <Input
                id="compaction-members"
                type="number"
                min={0}
                className="w-full font-mono text-sm sm:w-40"
                placeholder="0 = 默认 6"
                value={compactionMembers}
                disabled={!loaded || savingCompaction}
                onChange={(e) => setCompactionMembers(e.target.value)}
              />
              <Button onClick={saveCompaction} disabled={!loaded || savingCompaction}>
                保存
              </Button>
            </div>
            {/* B10:压缩器模型。规划器跑贵模型时，把机械的冷节点压缩钉在便宜模型上省钱;
                一次一发的设计让压缩对速度远比对话敏感，低价高速模型反而是更搭的选型。 */}
            <div className="flex flex-wrap items-center gap-2">
              <Label htmlFor="compactor-profile" className="w-40 text-sm">
                压缩器模型
              </Label>
              <Select value={compactorProfile} onValueChange={saveCompactorProfile}>
                <SelectTrigger id="compactor-profile" className="w-72">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="0">跟随规划器（默认）</SelectItem>
                  {llmProfileOpts.map((p) => (
                    <SelectItem key={p.id} value={p.id}>
                      {p.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <span className="text-muted-foreground text-xs">
                冷节点压缩是后台的一次性调用，适合钉在低价模型上省钱。钉住的配置被删/无 Key
                时自动落回跟随规划器；额度耗尽按绑定语义直接失败（换配置或改回「跟随规划器」）。
              </span>
            </div>
          </CardContent>
        </Card>

        <Card className="order-43">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <KeyboardIcon className="size-4" />
              会话输入框发送键位
            </CardTitle>
            <CardDescription>
              对话页与任务详情的主 Agent 会话输入框共用此设置，选择后立即生效、无需保存。
              <br />
              该偏好<b>只存在本浏览器</b>，不随账号同步，换浏览器或清理站点数据后需重新设置。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between gap-4">
            <Label htmlFor="chat-send-mode" className="font-normal text-muted-foreground text-sm">
              发送方式
            </Label>
            <Select value={sendMode} onValueChange={(v) => setChatSendMode(v as ChatSendMode)}>
              <SelectTrigger id="chat-send-mode" className="w-72">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CHAT_SEND_MODE_OPTIONS.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </CardContent>
        </Card>

        <Card className="order-51">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <SearchIcon className="size-4" />
              诊断与排障
            </CardTitle>
            <CardDescription>
              导出诊断包：设置、运行指标、任务/目标/意图、执行轨迹、漏洞/事实、事件时间线、
              分层日志（panic 聚合）、流量/代理/LLM 统计与数据完整性自检，打包为一个 zip。
              出问题时把这份文件发给开发即可定位，无需登录服务器（不含 LLM/代理凭据、流量与证据正文）。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-1 flex-col justify-center gap-4">
            <div className="flex items-center justify-between gap-3 rounded-md border px-3 py-2">
              <div className="min-w-0">
                <div className="text-sm">包含详细执行轨迹</div>
                <div className="text-muted-foreground text-xs">
                  带 worker 逐步工具轨迹（参数只保留形状摘要，不含命令/流量正文）与更大日志窗口，体积可达 50MB。
                </div>
              </div>
              <Switch checked={diagDetail} onCheckedChange={setDiagDetail} disabled={exportingDiag} />
            </div>
            <Button size="sm" variant="outline" onClick={exportDiagnostics} disabled={!loaded || exportingDiag}>
              {exportingDiag ? "导出中…" : "导出诊断包（zip）"}
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
