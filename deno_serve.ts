// 云端门户网关 — Deno Deploy 版（替代 Netlify Functions）
// 同时提供 API (/api) 和静态文件 (public/)
// 逻辑与 netlify/functions/api.mjs 完全一致，仅入口格式适配 Deno.serve()

import { serveDir } from "https://deno.land/std@0.224.0/http/file_server.ts";

const SB_URL = Deno.env.get("SUPABASE_URL")!;
const SB_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const AGENT_KEY = Deno.env.get("AGENT_KEY")!;

const sbHeaders = {
  apikey: SB_KEY,
  Authorization: `Bearer ${SB_KEY}`,
};

// ---------- Supabase REST helpers ----------
async function dbSelect(table: string, query: string) {
  const res = await fetch(`${SB_URL}/rest/v1/${table}?${query}`, { headers: sbHeaders });
  if (!res.ok) throw new Error(`db select ${table}: ${res.status} ${await res.text()}`);
  return res.json();
}

async function dbInsert(table: string, row: Record<string, unknown>) {
  const res = await fetch(`${SB_URL}/rest/v1/${table}`, {
    method: "POST",
    headers: { ...sbHeaders, "Content-Type": "application/json", Prefer: "return=representation" },
    body: JSON.stringify(row),
  });
  if (!res.ok) throw new Error(`db insert ${table}: ${res.status} ${await res.text()}`);
  return (await res.json())[0];
}

async function dbUpdate(table: string, filter: string, patch: Record<string, unknown>) {
  const res = await fetch(`${SB_URL}/rest/v1/${table}?${filter}`, {
    method: "PATCH",
    headers: { ...sbHeaders, "Content-Type": "application/json", Prefer: "return=representation" },
    body: JSON.stringify(patch),
  });
  if (!res.ok) throw new Error(`db update ${table}: ${res.status} ${await res.text()}`);
  return res.json();
}

async function dbRpc(fn: string, args: Record<string, unknown> = {}) {
  const res = await fetch(`${SB_URL}/rest/v1/rpc/${fn}`, {
    method: "POST",
    headers: { ...sbHeaders, "Content-Type": "application/json" },
    body: JSON.stringify(args),
  });
  if (!res.ok) throw new Error(`rpc ${fn}: ${res.status} ${await res.text()}`);
  return res.json();
}

async function storageUpload(bucket: string, path: string, buffer: Uint8Array, contentType: string) {
  const safePath = encodeURIComponent(path).replace(/%2F/g, "/");
  const res = await fetch(`${SB_URL}/storage/v1/object/${bucket}/${safePath}`, {
    method: "POST",
    headers: { ...sbHeaders, "Content-Type": contentType || "application/octet-stream", "x-upsert": "true" },
    body: buffer as BodyInit,
  });
  if (!res.ok) throw new Error(`storage upload: ${res.status} ${await res.text()}`);
}

async function storageDownload(bucket: string, path: string): Promise<Uint8Array> {
  const safePath = encodeURIComponent(path).replace(/%2F/g, "/");
  const res = await fetch(`${SB_URL}/storage/v1/object/${bucket}/${safePath}`, { headers: sbHeaders });
  if (!res.ok) throw new Error(`storage download: ${res.status} ${await res.text()}`);
  return new Uint8Array(await res.arrayBuffer());
}

// ---------- 鉴权 ----------
let _accessCodeCache = { value: "", ts: 0 };
async function getAccessCode(): Promise<string> {
  if (_accessCodeCache.value && Date.now() - _accessCodeCache.ts < 60_000) return _accessCodeCache.value;
  const rows = await dbSelect("portal_settings", "key=eq.access_code&select=value");
  const v = rows[0]?.value || "";
  _accessCodeCache = { value: v, ts: Date.now() };
  return v;
}

async function getSetting(key: string): Promise<string> {
  const rows = await dbSelect("portal_settings", `key=eq.${key}&select=value`);
  return rows[0]?.value || "";
}

async function isAdmin(payload: Record<string, unknown>): Promise<boolean> {
  if (!payload.admin_code) return false;
  const ac = await getSetting("admin_code");
  return !!ac && payload.admin_code === ac;
}

const AGENT_ONLINE_WINDOW_MS = 25_000;
const LIST_FIELDS = "id,template_type,created_by,sys_username,status,progress,step,error,created_at,claimed_at,completed_at,output_files,summary";

function json(status: number, body: unknown) {
  return { status, body };
}

// ---------- 核心 API 处理 ----------
async function handleApi(payload: Record<string, any>): Promise<{ status: number; body: unknown }> {
  const action = payload.action as string | undefined;

  // ============ agent 专用操作 ============
  if (action?.startsWith("agent_")) {
    if (!AGENT_KEY || payload.agent_key !== AGENT_KEY) return json(403, { error: "agent 鉴权失败" });

    if (action === "agent_poll") {
      await dbUpdate("agent_state", "id=eq.1", { last_seen: new Date().toISOString(), info: payload.info || null });
      const claimed = await dbRpc("claim_next_task");
      if (claimed[0]) return json(200, { task: claimed[0] });
      const acts = await dbSelect("cloud_tasks",
        "action_state=eq.pending&select=id,action_type,action_file,local_sid,template_type,created_by&order=created_at&limit=1");
      if (acts[0]) {
        const took = await dbUpdate("cloud_tasks", `id=eq.${acts[0].id}&action_state=eq.pending`, { action_state: "running" });
        if (took.length) return json(200, { task: null, upload_action: acts[0] });
      }
      const cfgs = await dbSelect("config_requests",
        "state=eq.pending&select=id,op,mapping_name,payload&order=created_at&limit=1");
      if (cfgs[0]) {
        const took = await dbUpdate("config_requests", `id=eq.${cfgs[0].id}&state=eq.pending`, { state: "running" });
        if (took.length) return json(200, { task: null, config_request: cfgs[0] });
      }
      return json(200, { task: null });
    }

    if (action === "agent_config_done") {
      await dbUpdate("config_requests", `id=eq.${payload.request_id}`, {
        state: payload.error ? "failed" : "completed",
        result: payload.result || null,
        error: payload.error || null,
        completed_at: new Date().toISOString(),
      });
      return json(200, { ok: true });
    }

    if (action === "agent_action_update") {
      const patch: Record<string, unknown> = {};
      for (const k of ["action_state", "action_result", "action_log"]) {
        if (payload[k] !== undefined) patch[k] = payload[k];
      }
      await dbUpdate("cloud_tasks", `id=eq.${payload.task_id}`, patch);
      return json(200, { ok: true });
    }

    if (action === "agent_update") {
      const patch: Record<string, unknown> = {};
      for (const k of ["status", "progress", "step", "log", "error", "summary", "login_state", "login_message"]) {
        if (payload[k] !== undefined) patch[k] = payload[k];
      }
      await dbUpdate("cloud_tasks", `id=eq.${payload.task_id}`, patch);
      return json(200, { ok: true });
    }

    if (action === "agent_get_tfa") {
      const rows = await dbSelect("cloud_tasks", `id=eq.${payload.task_id}&select=tfa_code`);
      return json(200, { tfa_code: rows[0]?.tfa_code || null });
    }

    if (action === "agent_clear_tfa") {
      await dbUpdate("cloud_tasks", `id=eq.${payload.task_id}`, { tfa_code: null });
      return json(200, { ok: true });
    }

    if (action === "agent_clear_creds") {
      await dbUpdate("cloud_tasks", `id=eq.${payload.task_id}`,
        { sys_password: null, cainiao_password: null, reg_access_token: null });
      return json(200, { ok: true });
    }

    if (action === "agent_download_input") {
      const buf = await storageDownload("task-inputs", payload.path as string);
      return json(200, { content_base64: btoa(String.fromCharCode(...buf)) });
    }

    if (action === "agent_upload_output") {
      const { task_id, name, content_base64 } = payload as { task_id: string; name: string; content_base64: string };
      const buf = Uint8Array.from(atob(content_base64), c => c.charCodeAt(0));
      const rows = await dbSelect("cloud_tasks", `id=eq.${task_id}&select=output_files`);
      const files = rows[0]?.output_files || [];
      const ext = (name.match(/\.[A-Za-z0-9]+$/) || [".xlsx"])[0];
      const path = `${task_id}/out_${files.length}${ext}`;
      await storageUpload("task-outputs", path, buf,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
      files.push({ name, path, size: buf.length });
      await dbUpdate("cloud_tasks", `id=eq.${task_id}`, { output_files: files });
      return json(200, { ok: true });
    }

    if (action === "agent_complete") {
      const patch: Record<string, unknown> = {
        status: payload.error ? "failed" : "completed",
        error: payload.error || null,
        summary: payload.summary || null,
        local_sid: payload.local_sid || null,
        completed_at: new Date().toISOString(),
        sys_password: null,
        cainiao_password: null,
        reg_access_token: null,
        tfa_code: null,
      };
      if (!payload.error) patch.progress = 100;
      await dbUpdate("cloud_tasks", `id=eq.${payload.task_id}`, patch);
      return json(200, { ok: true });
    }

    return json(400, { error: `未知 agent 操作: ${action}` });
  }

  // ============ 同事操作（需访问码） ============
  const code = await getAccessCode();
  if (!code || payload.access_code !== code) return json(403, { error: "访问码错误" });

  if (action === "login") return json(200, { ok: true });

  if (action === "create_task") {
    const row = {
      template_type: payload.template_type || "",
      created_by: (payload.created_by || "").slice(0, 30),
      status: "uploading",
      sys_username: (payload.sys_username || "").trim() || null,
      sys_password: (payload.sys_password || "") || null,
      cainiao_username: (payload.cainiao_username || "").trim() || null,
      cainiao_password: (payload.cainiao_password || "") || null,
      reg_access_token: (payload.reg_access_token || "") || null,
    };
    if (!row.sys_username || !row.sys_password)
      return json(400, { error: "请填写 ffnc/XMS 账号和密码" });
    if (row.template_type === "登记系统" && !row.reg_access_token)
      return json(400, { error: '请先完成登记系统授权（在登记系统板块点"去授权"）' });
    const t = await dbInsert("cloud_tasks", row);
    return json(200, { task_id: t.id });
  }

  if (action === "upload_input") {
    const { task_id, name, content_base64 } = payload as { task_id: string; name: string; content_base64: string };
    if (!/\.(xlsx|xls)$/i.test(name)) return json(400, { error: "仅支持Excel文件" });
    const buf = Uint8Array.from(atob(content_base64), c => c.charCodeAt(0));
    const rows = await dbSelect("cloud_tasks", `id=eq.${task_id}&select=input_files`);
    const files = rows[0]?.input_files || [];
    const ext = (name.match(/\.[A-Za-z0-9]+$/) || [".xlsx"])[0];
    const path = `${task_id}/in_${files.length}${ext}`;
    await storageUpload("task-inputs", path, buf,
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    files.push({ name, path, size: buf.length });
    await dbUpdate("cloud_tasks", `id=eq.${task_id}`, { input_files: files });
    return json(200, { ok: true });
  }

  if (action === "submit_task") {
    const rows = await dbUpdate("cloud_tasks", `id=eq.${payload.task_id}&status=eq.uploading`, {
      status: "pending", step: "排队等待本机领取",
    });
    if (!rows.length) return json(400, { error: "任务状态异常，无法提交" });
    return json(200, { ok: true });
  }

  if (action === "list_tasks") {
    const admin = await isAdmin(payload);
    const viewer = String(payload.viewer || "").trim();
    let filter = `select=${LIST_FIELDS}&order=created_at.desc&limit=30`;
    if (!admin) {
      if (!viewer) return json(200, { tasks: [], agent_online: false, agent_last_seen: null });
      filter = `sys_username=eq.${encodeURIComponent(viewer)}&${filter}`;
    }
    const [tasks, agents] = await Promise.all([
      dbSelect("cloud_tasks", filter),
      dbSelect("agent_state", "id=eq.1&select=last_seen"),
    ]);
    const lastSeen = agents[0]?.last_seen ? new Date(agents[0].last_seen).getTime() : 0;
    return json(200, {
      tasks,
      is_admin: admin,
      agent_online: Date.now() - lastSeen < AGENT_ONLINE_WINDOW_MS,
      agent_last_seen: agents[0]?.last_seen || null,
    });
  }

  if (action === "request_upload") {
    const VALID_TYPES = ["import_ffnc", "upload_notification", "upload_no_tracking"];
    if (!VALID_TYPES.includes(payload.upload_type as string)) return json(400, { error: "未知上传类型" });
    const rows = await dbSelect("cloud_tasks",
      `id=eq.${payload.task_id}&select=sys_username,status,action_state,local_sid`);
    if (!rows.length) return json(404, { error: "任务不存在" });
    const t = rows[0];
    const viewer = String(payload.viewer || "").trim();
    if (t.sys_username && t.sys_username !== viewer && !(await isAdmin(payload)))
      return json(403, { error: "无权操作该任务" });
    if (t.status !== "completed") return json(400, { error: "任务尚未处理完成，无法上传" });
    if (["pending", "running"].includes(t.action_state))
      return json(400, { error: "已有上传动作正在执行，请等待完成" });
    if (!t.local_sid) return json(400, { error: "该任务缺少本机会话记录（旧任务），请重新处理后再上传" });
    await dbUpdate("cloud_tasks", `id=eq.${payload.task_id}`, {
      action_type: payload.upload_type,
      action_file: String(payload.filename || ""),
      action_state: "pending",
      action_result: null,
      action_log: null,
    });
    return json(200, { ok: true });
  }

  if (action === "submit_tfa") {
    const c = String(payload.code || "").trim();
    if (!c) return json(400, { error: "请输入验证码" });
    const rows0 = await dbSelect("cloud_tasks", `id=eq.${payload.task_id}&select=sys_username`);
    if (!rows0.length) return json(404, { error: "任务不存在" });
    const viewer0 = String(payload.viewer || "").trim();
    if (rows0[0].sys_username !== viewer0 && !(await isAdmin(payload)))
      return json(403, { error: "无权操作该任务" });
    await dbUpdate("cloud_tasks", `id=eq.${payload.task_id}`,
      { tfa_code: c, login_message: "验证码已提交，正在登录..." });
    return json(200, { ok: true });
  }

  if (action === "get_task") {
    const rows = await dbSelect("cloud_tasks", `id=eq.${payload.task_id}&select=*`);
    if (!rows.length) return json(404, { error: "任务不存在" });
    const t = rows[0];
    const viewer = String(payload.viewer || "").trim();
    if (t.sys_username && t.sys_username !== viewer && !(await isAdmin(payload)))
      return json(403, { error: "无权查看该任务" });
    delete t.sys_password;
    delete t.cainiao_password;
    delete t.reg_access_token;
    delete t.tfa_code;
    return json(200, { task: t });
  }

  if (action === "download") {
    const p = String(payload.path || "");
    if (!/^[0-9a-f-]{36}\/[^/]+$/i.test(p)) return json(400, { error: "路径不合法" });
    const tid = p.split("/")[0];
    const rows = await dbSelect("cloud_tasks", `id=eq.${tid}&select=sys_username`);
    if (!rows.length) return json(404, { error: "任务不存在" });
    const viewer = String(payload.viewer || "").trim();
    if (rows[0].sys_username && rows[0].sys_username !== viewer && !(await isAdmin(payload)))
      return json(403, { error: "无权下载该任务的文件" });
    const buf = await storageDownload("task-outputs", p);
    return json(200, { name: p.split("/").pop(), content_base64: btoa(String.fromCharCode(...buf)) });
  }

  if (action === "admin_login") {
    if (await isAdmin(payload)) return json(200, { ok: true });
    return json(403, { error: "管理员密码错误" });
  }

  // ============ 配置管理 ============
  if (action === "config_request") {
    const op = payload.op === "write" ? "write" : "read";
    if (op === "write" && !(await isAdmin(payload)))
      return json(403, { error: "修改配置需要管理员密码" });
    const row = await dbInsert("config_requests", {
      op,
      mapping_name: String(payload.mapping_name || ""),
      payload: op === "write" ? { headers: payload.headers || [], rows: payload.rows || [] } : null,
      requested_by: (payload.viewer || "").slice(0, 40),
      state: "pending",
    });
    return json(200, { request_id: row.id });
  }

  if (action === "config_result") {
    const rows = await dbSelect("config_requests",
      `id=eq.${payload.request_id}&select=state,result,error`);
    if (!rows.length) return json(404, { error: "请求不存在" });
    return json(200, rows[0]);
  }

  return json(400, { error: `未知操作: ${action}` });
}

// ---------- Deno.serve 入口 ----------
Deno.serve(async (req: Request) => {
  const url = new URL(req.url);

  // CORS 预检
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    });
  }

  // API 路由
  if (url.pathname === "/api" && req.method === "POST") {
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(await req.text());
    } catch {
      return new Response(JSON.stringify({ error: "请求格式错误" }), {
        status: 400,
        headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" },
      });
    }
    try {
      const result = await handleApi(payload);
      return new Response(JSON.stringify(result.body), {
        status: result.status,
        headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" },
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return new Response(JSON.stringify({ error: msg }), {
        status: 500,
        headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" },
      });
    }
  }

  // 静态文件 (public/ 目录)
  return serveDir(req, { fsRoot: "public", showIndex: true });
});
