use hyper::{Body, Client, Request, Response, Uri};
use hyper::service::{make_service_fn, service_fn};
use hyper::client::HttpConnector;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use rustls::{ServerConfig, SupportedProtocolVersion};
use rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::{certs, rsa_private_keys, pkcs8_private_keys};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use serde_json::{Value, json};
use hyper::service::Service;
use serde::{Deserialize, Serialize};

use rustls::client::{ServerCertVerifier, ServerCertVerified};

struct CustomServerCertVerifier;

impl ServerCertVerifier for CustomServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 实现你的证书验证逻辑
        Ok(ServerCertVerified::assertion())
    }
}


type HttpClient = Client<HttpsConnector<HttpConnector>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    listen_port: u16,
    ignore_target_verify: bool,
    target_host: String,
    target_uri: String,
    cert_path: Option<String>,
    key_path: Option<String>,
    ca_path: Option<String>,
}

fn read_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = serde_json::from_str(&content)?;
    Ok(config)
}

async fn handle_request(req: Request<Body>, client: HttpClient, target_host:String, target_uri:String) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
    // 解析请求
    let (mut parts, body) = req.into_parts();

    /*
    // 读取 body 内容并解析为 JSON
    let body_bytes = hyper::body::to_bytes(body).await?;
    let body_json: Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?; // 将 serde_json::Error 转换为 Box<dyn Error>

    // 修改 JSON 数据
    let mut modified_json = body_json.clone();
    if let Value::Object(ref mut obj) = modified_json {
        // 修改 user 字段
        if let Some(user) = obj.get_mut("user") {
            if let Value::String(ref mut user_str) = user {
                user_str.push_str("1"); // 修改为 "test1"
            }
        }

        // 修改 password 字段
        if let Some(password) = obj.get_mut("password") {
            if let Value::String(ref mut password_str) = password {
                password_str.push_str("1"); // 修改为 "test1"
            }
        }

        // 添加 role 字段
        obj.insert("role".to_string(), json!("管理员"));
    }

    // 重新构建 body
    let new_body = Body::from(modified_json.to_string());
    */

    println!("Original parts:{:?}", parts);
    let orig_path = parts.uri.path();
    // 修改请求头（可选）
    parts.headers.remove("host");
    parts.headers.insert("host", target_host.parse().unwrap());

    // 构建新的请求
    let new_uri = target_uri.clone() + orig_path;
    let uri = new_uri.as_str();
    parts.uri = uri.parse::<Uri>().unwrap();
    println!("New parts:{:?}", parts);
    let new_req = Request::from_parts(parts, body);

    // 发送请求到目标服务器
    let res = client.request(new_req).await?;

    // 返回响应
    Ok(res)
}

async fn load_certs(path: &str) -> Vec<rustls::Certificate> {
    let mut file = File::open(path).await.unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).await.unwrap();
    certs(&mut &buf[..]).unwrap().into_iter().map(rustls::Certificate).collect()
}

async fn load_custom_ca(ca_path: Option<&str>) -> Result<RootCertStore, Box<dyn std::error::Error>> {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            // 使用 as_ref() 借用 Der<'_> 的内容，并将其转换为 Vec<u8>
            let name_constraints = ta.name_constraints.as_ref().map(|nc| nc.as_ref().to_vec());
            
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject.as_ref().to_vec(),
                ta.subject_public_key_info.as_ref().to_vec(),
                name_constraints,
            )
        })
    );
    if ca_path.is_none() {
        return Ok(root_store)
    }
    let path = ca_path.unwrap();
    // 1. 加载 CA 证书
    let ca_file = std::fs::File::open(path)?;
    let mut ca_reader = std::io::BufReader::new(ca_file);

    // 2. 解析证书
    let ca_certs = certs(&mut ca_reader)?;

    // 3. 添加根证书存储
    for cert in ca_certs {
        root_store.add_parsable_certificates(&[cert]);
    }

    Ok(root_store)
}

async fn load_private_key(path: &str) -> Result<rustls::PrivateKey, Box<dyn std::error::Error + Send + Sync>> {
    let mut file = File::open(path).await.unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).await.unwrap();

    // 尝试解析 RSA 私钥
    if let Ok(keys) = rsa_private_keys(&mut &buf[..]) {
        if !keys.is_empty() {
            return Ok(rustls::PrivateKey(keys[0].clone()));
        }
    }

    // 尝试解析 PKCS8 私钥
    if let Ok(keys) = pkcs8_private_keys(&mut &buf[..]) {
        if !keys.is_empty() {
            return Ok(rustls::PrivateKey(keys[0].clone()));
        }
    }

    // 如果两种格式都解析失败，返回错误
    Err("Failed to parse private key: no valid RSA or PKCS8 key found".into())
}

#[tokio::main]
async fn main() {
    let config = read_config("config.json").expect("Failed to read config");
    println!("config:{:?}", config);
    // 加载 TLS 证书
    let cert_path = match &config.cert_path {
        None => "cert.pem",
        Some(path) => {
            path.as_str()
        }
    };
    let certs = load_certs(cert_path).await;

    // 加载私钥
    let key_path = match &config.key_path {
        None => "key.pem",
        Some(path) => path.as_str()
    };
    let key = match load_private_key(key_path).await {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to load private key: {}", e);
            return;
        }
    };

    // 配置 TLS
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();

    // 创建 TlsAcceptor
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // 创建 HTTPS 客户端
    let ca_path = match &config.key_path {
        None => None,
        Some(path) => Some(path.as_str())
    };
    let root_store = load_custom_ca(ca_path).await.expect("failed to create client root store");
    let client_tls_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let client_tls_config1 = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(CustomServerCertVerifier))
        .with_no_client_auth();
    
    let https = match config.ignore_target_verify {
        true => {
            HttpsConnectorBuilder::new()
            //.with_native_roots()
            .with_tls_config(client_tls_config1)
            .https_only()
            .enable_http1()
            .build()
        }
        false => {
            HttpsConnectorBuilder::new()
            //.with_native_roots()
            .with_tls_config(client_tls_config)
            .https_only()
            .enable_http1()
            .build()
        }
    };

    let client = Client::builder().build::<_, hyper::Body>(https);

    // 创建服务
    let target_host = config.target_host.clone();
    let target_uri = config.target_uri.clone();
    let make_svc = make_service_fn(move |_conn| {
        let client = client.clone();
        let host = target_host.clone();
        let uri = target_uri.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle_request(req, client.clone(), host.clone(), uri.clone())
            }))
        }
    });

    // 绑定地址
    let addr = SocketAddr::from(([0, 0, 0, 0], config.listen_port));
    let listener = TcpListener::bind(&addr).await.unwrap();

    // 启动服务器
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let tls_acceptor = tls_acceptor.clone();
        let mut make_svc = make_svc.clone();

        tokio::spawn(async move {
            if let Ok(stream) = tls_acceptor.accept(stream).await {
                let service = make_svc.call(&()).await.unwrap();
                let _ = hyper::server::conn::Http::new()
                    .serve_connection(stream, service)
                    .await;
            }
        });
    }
}
