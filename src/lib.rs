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
        .on_async("/link/:proxy", link_with_proxy)
        .on_async("/", |req, _| async move {
            let url = req.url()?;
            let mut new_url = url.clone();
            new_url.set_path("/link");
            Response::redirect(new_url)
        })
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
    generate_link_page(cx.data.clone(), None)
}

fn generate_link_page(config: Config, path: Option<String>) -> Result<Response> {
    let host = config.host.to_string();
    let uuid = config.uuid.to_string();
    let path_segment = path.unwrap_or_else(|| "proxyIP-proxyPort".to_string());

    let vmess = |tls: bool| {
        let config = serde_json::json!({
            "v": "2",
            "ps": if tls { "[XSM]-VMESS-TLS" } else { "[XSM]-VMESS-NTLS" },
            "add": host,
            "port": if tls { "443" } else { "80" },
            "id": uuid,
            "aid": "0",
            "scy": "zero",
            "net": "ws",
            "type": "none",
            "host": host,
            "path": format!("/{}", path_segment),
            "tls": if tls { "tls" } else { "" },
            "sni": host,
            "alpn": ""
        });
        format!("vmess://{}", URL_SAFE.encode(config.to_string()))
    };

    let vless = |tls: bool| {
        format!(
            "vless://{}@{}:{}?type=ws&security={}&host={}&sni={}&path=/{}#[XSM]-VLESS-{}",
            uuid,
            host,
            if tls { "443" } else { "80" },
            if tls { "tls" } else { "none" },
            host,
            host,
            path_segment,
            if tls { "TLS" } else { "NTLS" }
        )
    };

    let trojan = |tls: bool| {
        format!(
            "trojan://{}@{}:{}?type=ws&security={}&host={}&sni={}&path=/{}#[XSM]-TROJAN-{}",
            uuid,
            host,
            if tls { "443" } else { "80" },
            if tls { "tls" } else { "none" },
            host,
            host,
            path_segment,
            if tls { "TLS" } else { "NTLS" }
        )
    };

    let ss = |tls: bool| {
        let base64_user = base64::engine::general_purpose::STANDARD.encode(format!("none:{}", uuid));
        let port = if tls { "443" } else { "80" };
        let security = if tls { "tls" } else { "none" };
        let label = if tls { "TLS" } else { "NTLS" };
        format!(
            "ss://{}@{}:{}?encryption=none&type=ws&host={}&path=/{}&security={}&fp=random{}#[XSM]-SS-{}",
            base64_user,
            host,
            port,
            host,
            path_segment,
            security,
            if tls { format!("&sni={}", host) } else { "".to_string() },
            label
        )
    };

    let cards = vec![
        ("VMESS TLS", vmess(true), "vmess_tls"),
        ("VMESS NTLS", vmess(false), "vmess_ntls"),
        ("VLESS TLS", vless(true), "vless_tls"),
        ("VLESS NTLS", vless(false), "vless_ntls"),
        ("TROJAN TLS", trojan(true), "trojan_tls"),
        ("TROJAN NTLS", trojan(false), "trojan_ntls"),
        ("SHADOWSOCKS TLS", ss(true), "ss_tls"),
        ("SHADOWSOCKS NTLS", ss(false), "ss_ntls"),
    ]
    .iter()
    .map(|(title, link, id)| format!(
        r#"<div class="card">
  <div class="protocol">{}</div>
  <div class="linkbox">
    <span id="{}">{}</span>
  </div>
  <button class="copy" onclick="copyText('{}', this)">Salin</button>
</div>"#,
        title, id, link, id
    ))
    .collect::<Vec<_>>()
    .join("\n");

    let html = format!(
    r#"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>XSM | SIREN | INFORMATION | ACCOUNT</title>
  <style>
    :root {{
      --bg: #f3f4f6;
      --card: #ffffff;
      --text: #1f2937;
      --linkbox: #d1d5db;
      --copy: #3b82f6;
      --copy-hover: #2563eb;
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
      margin: 0;
      padding: 2rem;
      display: flex;
      flex-direction: column;
      align-items: center;
    }}

    canvas#bg {{
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      z-index: -1;
    }}

    .toggle {{
      margin-bottom: 2rem;
      background: transparent;
      border: none;
      cursor: pointer;
      font-size: 1.5rem;
    }}

    .toggle svg {{
      width: 32px;
      height: 32px;
      fill: var(--text);
      transition: transform 0.3s;
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
    }}

    .protocol {{
      font-weight: bold;
      font-size: 1.2rem;
      margin-bottom: 0.75rem;
      color: #facc15;
    }}

    .linkbox {{
      background: var(--linkbox);
      padding: 0.75rem 1rem;
      border-radius: 0.5rem;
      font-size: 0.95rem;
      overflow-x: auto;
      border: 2px dashed lime;
    }}

    .copy {{
      cursor: pointer;
      margin-top: 0.75rem;
      padding: 0.5rem 1rem;
      background: var(--copy);
      color: white;
      border: none;
      border-radius: 0.375rem;
      font-weight: bold;
      transition: background 0.3s ease;
    }}

    .copy:hover {{
      background: var(--copy-hover);
    }}

    .copied {{
      background: var(--copied) !important;
    }}
  </style>
</head>
<body>
  <canvas id="bg"></canvas>
  <button class="toggle" onclick="toggleTheme()">
    <svg id="theme-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
      <path d="M12 2a1 1 0 011 1v1a1 1 0 01-2 0V3a1 1 0 011-1zm0 18a1 1 0 011 1v1a1 1 0 01-2 0v-1a1 1 0 011-1zm10-8a1 1 0 01-1 1h-1a1 1 0 110-2h1a1 1 0 011 1zM4 12a1 1 0 01-1 1H2a1 1 0 110-2h1a1 1 0 011 1z"/> 
    </svg>
  </button>
  <h1>Account Configuration</h1>
  {cards}
  <script>
    const html = document.documentElement;
    const icon = document.getElementById("theme-icon");
    const savedTheme = localStorage.getItem("theme");

    function setIcon(theme) {{
      icon.innerHTML = theme === "dark"
        ? `<path d="M21.64 13.65A9 9 0 1110.35 2.36 7 7 0 0021.64 13.65z"/>`
        : `<path d="M12 2a1 1 0 011 1v1a1 1 0 01-2 0V3a1 1 0 011-1z"/>`;
    }}

    if (savedTheme) {{
      html.setAttribute("data-theme", savedTheme);
      setIcon(savedTheme);
    }} else {{
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      const theme = prefersDark ? "dark" : "light";
      html.setAttribute("data-theme", theme);
      setIcon(theme);
    }}

    function toggleTheme() {{
      const current = html.getAttribute("data-theme");
      const newTheme = current === "dark" ? "light" : "dark";
      html.setAttribute("data-theme", newTheme);
      localStorage.setItem("theme", newTheme);
      setIcon(newTheme);
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

    // Rain drop animation
    const canvas = document.getElementById("bg");
    const ctx = canvas.getContext("2d");
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const drops = Array.from({{ length: 100 }}).map(() => ({{
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      speed: Math.random() * 4 + 2,
      length: Math.random() * 20 + 10,
      color: Math.random() > 0.5 ? 'magenta' : 'lime'
    }}));

    function drawRain() {{
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      for (let d of drops) {{
        ctx.beginPath();
        ctx.strokeStyle = d.color;
        ctx.lineWidth = 2;
        ctx.moveTo(d.x, d.y);
        ctx.lineTo(d.x, d.y + d.length);
        ctx.stroke();
        d.y += d.speed;
        if (d.y > canvas.height) {{
          d.y = -20;
          d.x = Math.random() * canvas.width;
        }}
      }}
      requestAnimationFrame(drawRain);
    }}

    drawRain();
    window.addEventListener('resize', () => {{
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    }});
  </script>
</body>
</html>"#,
    cards = cards
);

    Response::ok(html).map(|resp| resp.with_headers({
        let mut headers = Headers::new();
        headers.set("Content-Type", "text/html; charset=utf-8").ok();
        headers
    }))
}

async fn link_with_proxy(_: Request, mut cx: RouteContext<Config>) -> Result<Response> {
    if let Some(proxy) = cx.param("proxy") {
        if PROXYIP_PATTERN.is_match(proxy) {
            if let Some((addr, port_str)) = proxy.split_once('-') {
                if let Ok(port) = port_str.parse::<u16>() {
                    cx.data.proxy_addr = addr.to_string();
                    cx.data.proxy_port = port;
                    return generate_link_page(cx.data.clone(), Some(proxy.to_string()));
                }
            }
        }
    }

    // Fallback ke default jika format salah
    generate_link_page(cx.data.clone(), None)
}
