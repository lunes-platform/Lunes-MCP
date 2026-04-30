use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct RunningServer {
    child: Child,
    addr: String,
    workdir: PathBuf,
}

impl RunningServer {
    fn start(api_key: Option<&str>, rate_per_second: u64, rate_burst: u32) -> Self {
        let port = unused_port();
        let addr = format!("127.0.0.1:{port}");
        let workdir = create_workdir(rate_per_second, rate_burst);

        let mut command = Command::new(env!("CARGO_BIN_EXE_lunes-mcp-server"));
        command
            .current_dir(&workdir)
            .env("LUNES_MCP_BIND", &addr)
            .env_remove("LUNES_MCP_API_KEY")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if let Some(api_key) = api_key {
            command.env("LUNES_MCP_API_KEY", api_key);
        }

        let mut child = command.spawn().expect("server process starts");
        wait_for_tcp(&addr, &mut child);

        Self {
            child,
            addr,
            workdir,
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.workdir);
    }
}

#[test]
fn rejects_request_without_api_key_when_auth_is_configured() {
    let server = RunningServer::start(Some("test-token"), 10, 20);

    let response = post_json_rpc(&server.addr, None, health_body());

    assert!(response.starts_with("HTTP/1.1 401"));
    assert!(response.contains(r#""code":-32090"#));
}

#[test]
fn accepts_request_with_bearer_api_key() {
    let server = RunningServer::start(Some("test-token"), 10, 20);

    let response = post_json_rpc(&server.addr, Some("Bearer test-token"), health_body());

    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains(r#""status":"ok"#));
}

#[test]
fn rate_limit_rejects_requests_after_burst() {
    let server = RunningServer::start(Some("test-token"), 1, 1);

    let first = post_json_rpc(&server.addr, Some("Bearer test-token"), health_body());
    assert!(first.starts_with("HTTP/1.1 200"));

    let responses: Vec<String> = (0..8)
        .map(|_| post_json_rpc(&server.addr, Some("Bearer test-token"), health_body()))
        .collect();
    let rate_limited = responses
        .iter()
        .find(|response| response.starts_with("HTTP/1.1 429"));

    assert!(
        rate_limited.is_some(),
        "expected at least one rate-limited response, got: {responses:#?}"
    );
    assert!(rate_limited.unwrap().contains(r#""code":-32099"#));
}

fn health_body() -> &'static str {
    r#"{"jsonrpc":"2.0","id":1,"method":"mcp_health","params":{}}"#
}

fn post_json_rpc(addr: &str, authorization: Option<&str>, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect to server");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");

    let auth_header = authorization
        .map(|value| format!("Authorization: {value}\r\n"))
        .unwrap_or_default();

    let request = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nConnection: close\r\n{auth_header}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );

    stream
        .write_all(request.as_bytes())
        .expect("write HTTP request");

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read HTTP response");
    response
}

fn wait_for_tcp(addr: &str, child: &mut Child) {
    for _ in 0..80 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }

        if let Some(status) = child.try_wait().expect("check server status") {
            panic!("server exited before accepting connections: {status}");
        }

        thread::sleep(Duration::from_millis(50));
    }

    panic!("server did not accept connections on {addr}");
}

fn unused_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("read local addr").port()
}

fn create_workdir(rate_per_second: u64, rate_burst: u32) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "lunes-mcp-security-test-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create test workdir");
    fs::write(
        path.join("agent_config.toml"),
        format!(
            r#"
[network]
rpc_url = "wss://ws.lunes.io"

[agent.wallet]
mode = "prepare_only"

[agent.permissions]
allowed_extrinsics = []
daily_limit_lunes = 0

[server]
bind_address = "127.0.0.1"
port = 9950
rate_limit_per_second = {rate_per_second}
rate_limit_burst = {rate_burst}
"#
        ),
    )
    .expect("write test config");
    path
}
