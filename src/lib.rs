mod common;
mod config;
mod proxy;

use crate::config::Config;
use crate::proxy::*;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde::Serialize;
use uuid::Uuid;
use worker::*;
use once_cell::sync::Lazy;
use regex::Regex;

static PROXYIP_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^.+-\d+$").unwrap());

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    let uuid = env
        .var("UUID")
        .map(|x| Uuid::parse_str(&x.to_string()).unwrap_or_default())?;
    let host = req.url()?.host().map(|x| x.to_string()).unwrap_or_default();
    let config = Config {
        uuid,
        host: host.clone(),
        proxy_addr: host.clone(),
        proxy_port: 80,
    };

    Router::with_data(config)
        .on("/link", link)
        .on_async("/:proxyip", tunnel)
        .run(req, env)
        .await
}

async fn tunnel(req: Request, mut cx: RouteContext<Config>) -> Result<Response> {
    if let Some(proxyip) = cx.param("proxyip") {
        if PROXYIP_PATTERN.is_match(proxyip) {
            if let Some((addr, port_str)) = proxyip.split_once('-') {
                if let Ok(port) = port_str.parse() {
                    cx.data.proxy_addr = addr.to_string();
                    cx.data.proxy_port = port;
                }
            }
        }
    }

    let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
    if upgrade == "websocket" {
        let WebSocketPair { server, client } = WebSocketPair::new()?;
        server.accept()?;

        wasm_bindgen_futures::spawn_local(async move {
            let events = server.events().unwrap();
            if let Err(e) = ProxyStream::new(cx.data, &server, events).process().await {
                console_log!("[tunnel]: {}", e);
            }
        });

        Response::from_websocket(client)
    } else {
        let req = Fetch::Url(Url::parse("https://example.com")?);
        req.send().await
    }
}

fn link(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    let host = cx.data.host.to_string();
    let uuid = cx.data.uuid.to_string();

    let vmess = |tls: bool| {
        let config = serde_json::json!({
            "v": "2",
            "ps": if tls { "VMESS TLS" } else { "VMESS NTLS" },
            "add": host,
            "port": if tls { "443" } else { "80" },
            "id": uuid,
            "aid": "0",
            "scy": "zero",
            "net": "ws",
            "type": "none",
            "host": host,
            "path": format!("/{}-{}", cx.data.proxy_addr, cx.data.proxy_port),
            "tls": if tls { "tls" } else { "" },
            "sni": host,
            "alpn": ""
        });
        format!("vmess://{}", URL_SAFE.encode(config.to_string()))
    };

    let vless = |tls: bool| {
        format!(
            "vless://{}@{}:{}?type=ws&security={}&path=/{}-{}#VLESS_{}",
            uuid,
            host,
            if tls { "443" } else { "80" },
            if tls { "tls" } else { "none" },
            cx.data.proxy_addr,
            cx.data.proxy_port,
            if tls { "TLS" } else { "NTLS" }
        )
    };

    let trojan = |tls: bool| {
        format!(
            "trojan://{}@{}:{}?type=ws&security={}&path=/{}-{}#TROJAN_{}",
            uuid,
            host,
            if tls { "443" } else { "80" },
            if tls { "tls" } else { "none" },
            cx.data.proxy_addr,
            cx.data.proxy_port,
            if tls { "TLS" } else { "NTLS" }
        )
    };

    let html = format!(
    r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Link VPN</title>
  <style>
    :root {{
      --bg: #fff;
      --card: #fff;
      --text: #000;
      --linkbox: #e2e8f0;
      --copy: #0284c7;
      --copy-hover: #0369a1;
      --copied: #16a34a;
    }}

    [data-theme="dark"] {{
      --bg: #0f172a;
      --card: #1e293b;
      --text: #f8fafc;
      --linkbox: #334155;
      --copy: #0ea5e9;
      --copy-hover: #0284c7;
      --copied: #22c55e;
    }}

    body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'Segoe UI', sans-serif;
      padding: 2rem;
      display: flex;
      flex-direction: column;
      align-items: center;
    }}

    h1 {{
      margin-bottom: 2rem;
      font-size: 2.5rem;
      text-align: center;
      color: #38bdf8;
    }}

    .card {{
      background: var(--card);
      border-radius: 1rem;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      width: 100%;
      max-width: 700px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.1);
      transition: transform 0.3s ease;
    }}

    .card:hover {{
      transform: translateY(-5px);
    }}

    .protocol {{
      font-weight: bold;
      font-size: 1.2rem;
      margin-bottom: 0.75rem;
      color: #facc15;
    }}

    .linkbox {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: var(--linkbox);
      padding: 0.75rem 1rem;
      border-radius: 0.5rem;
      font-size: 0.95rem;
      overflow-x: auto;
    }}

    .copy {{
      cursor: pointer;
      padding: 0.5rem 1rem;
      background: var(--copy);
      color: white;
      border: none;
      border-radius: 0.375rem;
      margin-left: 1rem;
      font-weight: bold;
      transition: background 0.3s ease;
    }}

    .copy:hover {{
      background: var(--copy-hover);
    }}

    .copied {{
      background: var(--copied) !important;
    }}

    .toggle {{
      margin-bottom: 2rem;
      background: transparent;
      border: 2px solid #38bdf8;
      color: #38bdf8;
      padding: 0.5rem 1rem;
      border-radius: 0.5rem;
      cursor: pointer;
      font-weight: bold;
      transition: 0.3s;
    }}

    .toggle:hover {{
      background: #38bdf8;
      color: white;
    }}
  </style>
</head>
<body>
  <button class="toggle" onclick="toggleTheme()">Ganti Mode</button>
  <h1>Account Configuration</h1>
  {cards}
  <script>
    const html = document.documentElement;
    const savedTheme = localStorage.getItem("theme");

    if (savedTheme) {{
      html.setAttribute("data-theme", savedTheme);
    }} else {{
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      html.setAttribute("data-theme", prefersDark ? "dark" : "light");
    }}

    function toggleTheme() {{
      const current = html.getAttribute("data-theme");
      const newTheme = current === "dark" ? "light" : "dark";
      html.setAttribute("data-theme", newTheme);
      localStorage.setItem("theme", newTheme);
    }}

    function copyText(id, btn) {{
      const text = document.getElementById(id).textContent;
      navigator.clipboard.writeText(text).then(() => {{
        btn.classList.add('copied');
        btn.textContent = 'Disalin!';
        setTimeout(() => {{
          btn.classList.remove('copied');
          btn.textContent = 'Salin';
        }}, 1500);
      }});
    }}
  </script>
</body>
</html>"#,
    cards = [
        ("VLESS TLS", vless(true), "vless_tls"),
        ("VLESS NTLS", vless(false), "vless_ntls"),
        ("TROJAN TLS", trojan(true), "trojan_tls"),
        ("TROJAN NTLS", trojan(false), "trojan_ntls"),
        ("VMESS TLS", vmess(true), "vmess_tls"),
        ("VMESS NTLS", vmess(false), "vmess_ntls")
    ]
    .iter()
    .map(|(title, link, id)| format!(
        r#"<div class="card">
  <div class="protocol">{}</div>
  <div class="linkbox">
    <span id="{}">{}</span>
    <button class="copy" onclick="copyText('{}', this)">Salin</button>
  </div>
</div>"#,
        title, id, link, id
    ))
    .collect::<Vec<_>>()
    .join("\n")
);

    Response::from_html(&html)
}
