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
    body {{ background: #0f172a; color: #f8fafc; font-family: 'Segoe UI', sans-serif; padding: 2rem; }}
    .card {{ background: #1e293b; border-radius: 0.75rem; padding: 1.5rem; margin: 1rem 0; max-width: 700px; }}
    .protocol {{ font-weight: bold; margin-bottom: 0.5rem; }}
    .linkbox {{ display: flex; justify-content: space-between; background: #334155; padding: 0.5rem 1rem; border-radius: 0.5rem; }}
    .copy {{ cursor: pointer; padding: 0.25rem 0.75rem; background: #0ea5e9; color: white; border: none; border-radius: 0.25rem; transition: 0.3s; }}
    .copy:hover {{ background: #0284c7; }}
    .copied {{ background: #22c55e !important; }}
  </style>
</head>
<body>
  <h1>Account Configuration</h1>
  {cards}
  <script>
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
