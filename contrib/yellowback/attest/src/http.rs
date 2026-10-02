// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The one HTTP client configuration for venues, endpoints and the node (audit D-3, D-4):
//! a total deadline per request, no redirects (a 3xx would carry the request headers — an API
//! key, the node's Basic auth — to whatever host the peer names), and bodies read in chunks
//! under a cap instead of buffered whole.

use std::collections::BTreeMap;
use std::time::Duration;

/// A venue's or an endpoint's reply larger than this is refused, not buffered.
pub const VENUE_BODY_CAP: usize = 1 << 20;
/// The node is trusted; this only bounds a runaway reply.
pub const RPC_BODY_CAP: usize = 64 << 20;

pub fn client(timeout: Duration) -> reqwest::Result<reqwest::Client> {
    crate::tls::install();
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("yellowback-attest/3")
        .build()
}

/// The body of `resp`, at most `cap` bytes: `Content-Length` is checked first, then the stream
/// is read chunk by chunk and abandoned the moment it passes the cap.
pub async fn read_capped(mut resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, String> {
    if let Some(n) = resp.content_length() {
        if n > cap as u64 {
            return Err(format!("reply body {n} bytes exceeds the {cap} byte cap"));
        }
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > cap {
            return Err(format!("reply body exceeds the {cap} byte cap"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// GET `url` with `headers` and return the body on 2xx; any other status (a 3xx included, since
/// redirects are never followed) or an oversize body is the error string.
pub async fn get_capped(
    client: &reqwest::Client,
    url: &str,
    headers: &BTreeMap<String, String>,
    cap: usize,
) -> Result<Vec<u8>, String> {
    let mut req = client.get(url).header("Accept", "application/json");
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {}", status.as_u16()));
    }
    read_capped(resp, cap).await
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A tiny HTTP server: `/ok` answers JSON, `/redirect` 302s to `/leaked`, `/big` sends
    /// `VENUE_BODY_CAP + 1` bytes with a Content-Length, `/chunked-big` the same without one.
    pub struct TestServer {
        pub url: String,
        pub hits: Arc<Mutex<Vec<String>>>,
        server: Arc<tiny_http::Server>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl TestServer {
        pub fn start() -> Self {
            let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
            let url = format!("http://{}", server.server_addr());
            let hits: Arc<Mutex<Vec<String>>> = Default::default();
            let (srv, log, base) = (server.clone(), hits.clone(), url.clone());
            let thread = std::thread::spawn(move || {
                for req in srv.incoming_requests() {
                    let path = req.url().to_string();
                    log.lock().unwrap().push(path.clone());
                    let big = vec![b'x'; VENUE_BODY_CAP + 1];
                    let _ = match path.as_str() {
                        "/redirect" => req.respond(
                            tiny_http::Response::from_string("").with_status_code(302).with_header(
                                tiny_http::Header::from_bytes(&b"Location"[..], format!("{base}/leaked").as_bytes())
                                    .unwrap(),
                            ),
                        ),
                        "/big" => req.respond(tiny_http::Response::from_data(big)),
                        "/chunked-big" => req.respond(tiny_http::Response::new(
                            tiny_http::StatusCode(200),
                            vec![],
                            std::io::Cursor::new(big),
                            None,
                            None,
                        )),
                        _ => req.respond(tiny_http::Response::from_string(r#"{"price": "0.5", "volume": "10"}"#)),
                    };
                }
            });
            TestServer {
                url,
                hits,
                server,
                thread: Some(thread),
            }
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.server.unblock();
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    #[tokio::test]
    async fn redirects_are_refused_and_the_target_is_never_requested() {
        let s = TestServer::start();
        let c = client(Duration::from_secs(5)).unwrap();
        let key: BTreeMap<String, String> = [("x-cg-demo-api-key".to_string(), "k".to_string())].into();
        let none = BTreeMap::new();
        let err = get_capped(&c, &format!("{}/redirect", s.url), &key, VENUE_BODY_CAP)
            .await
            .unwrap_err();
        assert_eq!(err, "HTTP 302");
        assert_eq!(*s.hits.lock().unwrap(), vec!["/redirect"]);
        assert!(get_capped(&c, &format!("{}/ok", s.url), &none, VENUE_BODY_CAP)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn bodies_past_the_cap_are_refused_with_and_without_content_length() {
        let s = TestServer::start();
        let c = client(Duration::from_secs(5)).unwrap();
        let none = BTreeMap::new();
        for path in ["/big", "/chunked-big"] {
            let err = get_capped(&c, &format!("{}{path}", s.url), &none, VENUE_BODY_CAP)
                .await
                .unwrap_err();
            assert!(err.contains("byte cap"), "{path}: {err}");
        }
        assert!(get_capped(&c, &format!("{}/big", s.url), &none, VENUE_BODY_CAP + 1)
            .await
            .is_ok());
    }
}
