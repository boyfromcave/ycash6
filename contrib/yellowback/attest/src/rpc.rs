//! Minimal JSON-RPC 1.0 client over HTTP, a port of `Node` in `yellowback_price.py`: basic auth
//! from `rpc_user`/`rpc_password` or the node's `.cookie` file (re-read on every call, so a node
//! restart with a fresh cookie needs no agent restart).

use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use serde_json::{json, Value};

use crate::config::NodeConfig;

#[derive(Debug)]
pub enum RpcError {
    /// The node answered with a JSON-RPC error object.
    Node { code: i64, message: String },
    /// Transport: connection refused, timeout, non-JSON reply, ...
    Transport(String),
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpcError::Node { code, message } => write!(f, "{message} (code {code})"),
            RpcError::Transport(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RpcError {}

#[derive(Clone)]
pub struct Node {
    url: String,
    cookie: Option<PathBuf>,
    static_auth: Option<String>,
    client: reqwest::Client,
    id: std::sync::Arc<AtomicU64>,
}

impl Node {
    pub fn new(cfg: &NodeConfig) -> Result<Self, RpcError> {
        crate::tls::install();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.timeout_seconds))
            .build()
            .map_err(|e| RpcError::Transport(e.to_string()))?;
        // `http://user:pass@host:port` is accepted as the Python client does.
        let mut url = cfg.rpc_url.clone();
        let mut static_auth = None;
        if let Some((scheme, rest)) = cfg.rpc_url.split_once("://") {
            if let Some((creds, host)) = rest.rsplit_once('@') {
                url = format!("{scheme}://{host}");
                static_auth = Some(creds.to_string());
            }
        }
        if let Some(u) = &cfg.user {
            static_auth = Some(format!("{u}:{}", cfg.password.clone().unwrap_or_default()));
        }
        Ok(Node {
            url,
            cookie: cfg.cookie.clone(),
            static_auth,
            client,
            id: Default::default(),
        })
    }

    fn auth_header(&self) -> Result<Option<String>, RpcError> {
        let creds = match (&self.cookie, &self.static_auth) {
            (Some(path), _) => Some(
                std::fs::read_to_string(path)
                    .map(|s| s.trim().to_string())
                    .map_err(|e| RpcError::Transport(format!("cookie {}: {e}", path.display())))?,
            ),
            (None, Some(s)) => Some(s.clone()),
            (None, None) => None,
        };
        Ok(creds.map(|c| format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(c))))
    }

    pub async fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, RpcError> {
        let id = self.id.fetch_add(1, Ordering::Relaxed) + 1;
        let body = json!({"jsonrpc": "1.0", "id": id, "method": method, "params": params});
        let mut req = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .json(&body);
        if let Some(a) = self.auth_header()? {
            req = req.header("Authorization", a);
        }
        let resp = req.send().await.map_err(|e| RpcError::Transport(e.to_string()))?;
        let status = resp.status();
        let raw = resp.bytes().await.map_err(|e| RpcError::Transport(e.to_string()))?;
        let reply: Value = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(_) => {
                let head = String::from_utf8_lossy(&raw[..raw.len().min(120)]).trim().to_string();
                return Err(RpcError::Node {
                    code: status.as_u16() as i64,
                    message: format!(
                        "HTTP {}: {}",
                        status.as_u16(),
                        if head.is_empty() { status.to_string() } else { head }
                    ),
                });
            }
        };
        if let Some(err) = reply.get("error").filter(|e| !e.is_null()) {
            return Err(RpcError::Node {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: err.get("message").and_then(Value::as_str).unwrap_or("").to_string(),
            });
        }
        Ok(reply.get("result").cloned().unwrap_or(Value::Null))
    }
}

/// A tiny in-process JSON-RPC server for the tests: each request is answered by `handler`.
#[cfg(test)]
pub mod mock {
    use super::*;
    use std::sync::{Arc, Mutex};

    pub type CallLog = Arc<Mutex<Vec<(String, Vec<Value>)>>>;

    pub struct MockNode {
        pub url: String,
        pub calls: CallLog,
        server: Arc<tiny_http::Server>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl MockNode {
        /// `handler(method, params) -> Ok(result) | Err((code, message))`; `expect_auth` is the
        /// `user:password` the server insists on (None: anything goes).
        pub fn start<F>(expect_auth: Option<&str>, handler: F) -> Self
        where
            F: Fn(&str, &[Value]) -> Result<Value, (i64, String)> + Send + Sync + 'static,
        {
            let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
            let url = format!("http://{}", server.server_addr());
            let calls: CallLog = Arc::new(Mutex::new(Vec::new()));
            let want = expect_auth.map(|a| format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(a)));
            let (srv, log) = (server.clone(), calls.clone());
            let thread = std::thread::spawn(move || {
                for mut req in srv.incoming_requests() {
                    let auth = req
                        .headers()
                        .iter()
                        .find(|h| h.field.equiv("Authorization"))
                        .map(|h| h.value.as_str().to_string());
                    if want.is_some() && auth != want {
                        let _ = req.respond(tiny_http::Response::from_string("").with_status_code(401));
                        continue;
                    }
                    let mut body = String::new();
                    std::io::Read::read_to_string(req.as_reader(), &mut body).unwrap();
                    let v: Value = serde_json::from_str(&body).unwrap();
                    let method = v["method"].as_str().unwrap_or("").to_string();
                    let params = v["params"].as_array().cloned().unwrap_or_default();
                    log.lock().unwrap().push((method.clone(), params.clone()));
                    let reply = match handler(&method, &params) {
                        Ok(r) => json!({"result": r, "error": null, "id": v["id"]}),
                        Err((code, message)) => {
                            json!({"result": null, "error": {"code": code, "message": message}, "id": v["id"]})
                        }
                    };
                    let _ = req.respond(tiny_http::Response::from_string(reply.to_string()).with_header(
                        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
                    ));
                }
            });
            MockNode {
                url,
                calls,
                server,
                thread: Some(thread),
            }
        }

        pub fn config(&self, user: Option<&str>, password: Option<&str>, cookie: Option<PathBuf>) -> NodeConfig {
            NodeConfig {
                rpc_url: self.url.clone(),
                cookie,
                user: user.map(String::from),
                password: password.map(String::from),
                timeout_seconds: 5,
            }
        }
    }

    impl Drop for MockNode {
        fn drop(&mut self) {
            self.server.unblock();
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockNode;
    use super::*;

    #[tokio::test]
    async fn calls_with_user_password_and_reads_results_and_errors() {
        let m = MockNode::start(Some("alice:s3cret"), |method, params| match method {
            "yed_getinfo" => Ok(json!({"height": 42, "network": "regtest"})),
            "yed_addattestation" => Err((-8, format!("attest-unknown-seq: {}", params[0]))),
            _ => Err((-32601, "Method not found".into())),
        });
        let node = Node::new(&m.config(Some("alice"), Some("s3cret"), None)).unwrap();
        let info = node.call("yed_getinfo", vec![]).await.unwrap();
        assert_eq!(info["height"], 42);
        let err = node.call("yed_addattestation", vec![json!("00ff")]).await.unwrap_err();
        assert!(matches!(&err, RpcError::Node { code: -8, message } if message.starts_with("attest-unknown-seq")));
        let calls = m.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1], ("yed_addattestation".to_string(), vec![json!("00ff")]));
    }

    #[tokio::test]
    async fn cookie_auth_is_read_per_call_and_bad_auth_is_an_http_error() {
        let m = MockNode::start(Some("__cookie__:abc"), |_, _| Ok(json!(1)));
        let dir = tempfile::tempdir().unwrap();
        let cookie = dir.path().join(".cookie");
        std::fs::write(&cookie, "__cookie__:wrong\n").unwrap();
        let node = Node::new(&m.config(None, None, Some(cookie.clone()))).unwrap();
        let err = node.call("yed_getinfo", vec![]).await.unwrap_err();
        assert!(matches!(err, RpcError::Node { code: 401, .. }), "{err}");
        std::fs::write(&cookie, "__cookie__:abc\n").unwrap();
        assert_eq!(node.call("yed_getinfo", vec![]).await.unwrap(), json!(1));
    }

    #[tokio::test]
    async fn credentials_in_the_url_and_transport_failures() {
        let m = MockNode::start(Some("u:p"), |_, _| Ok(json!("ok")));
        let url = m.url.replace("http://", "http://u:p@");
        let cfg = NodeConfig {
            rpc_url: url,
            cookie: None,
            user: None,
            password: None,
            timeout_seconds: 5,
        };
        assert_eq!(Node::new(&cfg).unwrap().call("x", vec![]).await.unwrap(), json!("ok"));
        let dead = NodeConfig {
            rpc_url: "http://127.0.0.1:1".into(),
            cookie: None,
            user: None,
            password: None,
            timeout_seconds: 2,
        };
        assert!(matches!(
            Node::new(&dead).unwrap().call("x", vec![]).await,
            Err(RpcError::Transport(_))
        ));
    }
}
