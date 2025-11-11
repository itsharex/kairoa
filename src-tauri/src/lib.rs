use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose};
use dsa::{SigningKey, VerifyingKey, Components, Signature};
use rand::rngs::OsRng;
use pkcs8::{EncodePrivateKey, EncodePublicKey, DecodePrivateKey, DecodePublicKey, LineEnding};
use signature::{Signer, Verifier};
use sha2::{Sha256, Digest};
use der::Encode;
use pbkdf2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Pbkdf2,
};
use scrypt::{
    password_hash::{PasswordHash as ScryptPasswordHash, PasswordHasher as ScryptPasswordHasher, PasswordVerifier as ScryptPasswordVerifier, SaltString as ScryptSaltString},
    Scrypt,
};
use argon2::{
    password_hash::{PasswordHash as Argon2PasswordHash, PasswordHasher as Argon2PasswordHasher, PasswordVerifier as Argon2PasswordVerifier, SaltString as Argon2SaltString},
    Argon2, ParamsBuilder,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpRequest {
    url: String,
    method: String,
    headers: HashMap<String, String>,
    body: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct MultipartEntry {
    key: String,
    value: String,
    r#type: String, // "text" or "file"
    filename: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct MultipartBody {
    r#type: String,
    entries: Vec<MultipartEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
    error: Option<String>,
}

#[tauri::command]
async fn http_request(request: HttpRequest) -> Result<HttpResponse, String> {
    let client = reqwest::Client::new();
    
    let mut req_builder = match request.method.as_str() {
        "GET" => client.get(&request.url),
        "POST" => client.post(&request.url),
        "PUT" => client.put(&request.url),
        "DELETE" => client.delete(&request.url),
        "PATCH" => client.patch(&request.url),
        "HEAD" => client.head(&request.url),
        "OPTIONS" => client.request(reqwest::Method::OPTIONS, &request.url),
        _ => return Err(format!("Unsupported HTTP method: {}", request.method)),
    };

    // 添加请求头
    for (key, value) in request.headers {
        // 如果是 multipart 请求，Content-Type 会被 reqwest 自动设置
        if key.to_lowercase() != "content-type" || !request.body.as_ref().and_then(|b| serde_json::from_str::<MultipartBody>(b).ok()).map_or(false, |mb: MultipartBody| mb.r#type == "multipart") {
            req_builder = req_builder.header(&key, &value);
        }
    }

    // 添加请求体
    if let Some(body) = request.body {
        // 检查是否是 multipart 请求
        if let Ok(multipart_body) = serde_json::from_str::<MultipartBody>(&body) {
            if multipart_body.r#type == "multipart" {
                // 构建 multipart form
                let mut form = reqwest::multipart::Form::new();
                
                for entry in multipart_body.entries {
                    if entry.r#type == "file" {
                        // 解码 base64 文件
                        if let Ok(file_bytes) = general_purpose::STANDARD.decode(&entry.value) {
                            let part = if let Some(filename) = entry.filename.clone() {
                                let filename_clone = filename.clone();
                                reqwest::multipart::Part::bytes(file_bytes)
                                    .file_name(filename)
                                    .mime_str("application/octet-stream")
                                    .unwrap_or_else(|_| {
                                        // 如果 mime_str 失败，重新创建 Part（不使用 MIME 类型）
                                        // 这不应该发生，但为了安全起见我们处理它
                                        let file_bytes_copy = general_purpose::STANDARD.decode(&entry.value).unwrap();
                                        reqwest::multipart::Part::bytes(file_bytes_copy)
                                            .file_name(filename_clone)
                                    })
                            } else {
                                reqwest::multipart::Part::bytes(file_bytes)
                                    .mime_str("application/octet-stream")
                                    .unwrap_or_else(|_| {
                                        // 如果 mime_str 失败，重新创建 Part（不使用 MIME 类型）
                                        let file_bytes_copy = general_purpose::STANDARD.decode(&entry.value).unwrap();
                                        reqwest::multipart::Part::bytes(file_bytes_copy)
                                    })
                            };
                            form = form.part(entry.key, part);
                        }
                    } else {
                        // 文本字段
                        form = form.text(entry.key, entry.value);
                    }
                }
                
                req_builder = req_builder.multipart(form);
            } else {
                req_builder = req_builder.body(body);
            }
        } else {
            req_builder = req_builder.body(body);
        }
    }

    match req_builder.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let mut headers = HashMap::new();
            
            // 获取响应头
            for (key, value) in response.headers() {
                if let Ok(value_str) = value.to_str() {
                    headers.insert(key.to_string(), value_str.to_string());
                }
            }

            // 获取响应体
            let body = match response.text().await {
                Ok(text) => text,
                Err(e) => format!("Error reading response body: {}", e),
            };

            Ok(HttpResponse {
                status,
                headers,
                body,
                error: None,
            })
        }
        Err(e) => Ok(HttpResponse {
            status: 0,
            headers: HashMap::new(),
            body: String::new(),
            error: Some(e.to_string()),
        }),
    }
}

// DSA 密钥对响应结构
#[derive(Debug, Serialize, Deserialize)]
pub struct DsaKeyPair {
    public_key: String,
    private_key: String,
    format: String,
}

// 生成 DSA 密钥对（异步版本以避免阻塞）
#[tauri::command]
async fn generate_dsa_keypair(key_size: u32, format: String) -> Result<DsaKeyPair, String> {
    // 在单独的线程中生成密钥对以避免阻塞
    let result = tokio::task::spawn_blocking(move || {
        // 根据密钥大小生成密钥对
        let signing_key = match key_size {
            1024 => {
                // DSA 1024 位（已弃用，但仍支持）
                #[allow(deprecated)]
                let comp = Components::generate(&mut OsRng, dsa::KeySize::DSA_1024_160).clone();
                SigningKey::generate(&mut OsRng, comp)
            },
            2048 => {
                // DSA 2048 位
                let comp = Components::generate(&mut OsRng, dsa::KeySize::DSA_2048_256).clone();
                SigningKey::generate(&mut OsRng, comp)
            },
            3072 => {
                // DSA 3072 位
                let comp = Components::generate(&mut OsRng, dsa::KeySize::DSA_3072_256).clone();
                SigningKey::generate(&mut OsRng, comp)
            },
            _ => {
                return Err(format!("Unsupported key size: {}. Supported sizes: 1024, 2048, 3072", key_size));
            }
        };
        Ok(signing_key)
    }).await.map_err(|e| format!("Task execution failed: {}", e))?;
    
    let signing_key = result?;
    
    // 先获取公钥（克隆）
    let verifying_key = signing_key.verifying_key().clone();
    
    // 根据格式导出密钥
    let (public_key_str, private_key_str) = if format == "pem" {
        // PEM 格式
        let public_pem = verifying_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| format!("Failed to encode public key to PEM: {}", e))?;
        
        let private_pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| format!("Failed to encode private key to PEM: {}", e))?;
        
        (public_pem, private_pem.to_string())
    } else {
        // DER 格式（十六进制）
        let public_der = verifying_key
            .to_public_key_der()
            .map_err(|e| format!("Failed to encode public key to DER: {}", e))?;
        
        let private_der = signing_key
            .to_pkcs8_der()
            .map_err(|e| format!("Failed to encode private key to DER: {}", e))?;
        
        // 转换为十六进制字符串
        let public_hex = format_hex(public_der.as_bytes());
        let private_hex = format_hex(private_der.as_bytes());
        
        (public_hex, private_hex)
    };

    Ok(DsaKeyPair {
        public_key: public_key_str,
        private_key: private_key_str,
        format,
    })
}

// 格式化十六进制字符串（每 32 个字符换行）
fn format_hex(bytes: &[u8]) -> String {
    let hex: String = bytes.iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    
    let mut result = String::new();
    for (i, chunk) in hex.as_bytes().chunks(32).enumerate() {
        if i > 0 {
            result.push('\n');
        }
        result.push_str(&String::from_utf8_lossy(chunk));
    }
    result
}

// DSA 签名结果
#[derive(Debug, Serialize, Deserialize)]
pub struct DsaSignResult {
    signature: String,
}

// DSA 验证结果
#[derive(Debug, Serialize, Deserialize)]
pub struct DsaVerifyResult {
    valid: bool,
}

// DSA 签名
#[tauri::command]
fn dsa_sign(private_key_pem: String, message: String) -> Result<DsaSignResult, String> {
    // 从 PEM 导入私钥
    let signing_key = SigningKey::from_pkcs8_pem(&private_key_pem)
        .map_err(|e| format!("Failed to parse private key: {}", e))?;
    
    // 计算消息的 SHA-256 哈希
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    
    // 签名
    let signature: Signature = signing_key.sign(&hash);
    
    // DSA 签名使用 DER 编码
    let sig_bytes = signature.to_der()
        .map_err(|e| format!("Failed to encode signature: {}", e))?;
    let signature_base64 = general_purpose::STANDARD.encode(&sig_bytes);
    
    Ok(DsaSignResult {
        signature: signature_base64,
    })
}

// DSA 验证
#[tauri::command]
fn dsa_verify(public_key_pem: String, message: String, signature: String) -> Result<DsaVerifyResult, String> {
    // 从 PEM 导入公钥
    let verifying_key = VerifyingKey::from_public_key_pem(&public_key_pem)
        .map_err(|e| format!("Failed to parse public key: {}", e))?;
    
    // 解码签名
    let signature_bytes = general_purpose::STANDARD.decode(&signature)
        .map_err(|e| format!("Failed to decode signature: {}", e))?;
    
    let sig = Signature::try_from(signature_bytes.as_slice())
        .map_err(|e| format!("Invalid signature format: {}", e))?;
    
    // 计算消息的 SHA-256 哈希
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    
    // 验证签名
    let valid = verifying_key.verify(&hash, &sig).is_ok();
    
    Ok(DsaVerifyResult {
        valid,
    })
}

// Password Hash structures
#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordHashRequest {
    password: String,
    salt: Option<String>,
    algorithm: String,
    // PBKDF2 params
    iterations: Option<u32>,
    // Scrypt params
    n: Option<u32>,
    r: Option<u32>,
    p: Option<u32>,
    // Argon2 params
    memory: Option<u32>,
    argon2_iterations: Option<u32>,
    parallelism: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordHashResponse {
    hash: String,
    salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordVerifyRequest {
    password: String,
    hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordVerifyResponse {
    valid: bool,
}

// PBKDF2 Hash
#[tauri::command]
fn hash_pbkdf2(request: PasswordHashRequest) -> Result<PasswordHashResponse, String> {
    let salt_string = if let Some(salt) = request.salt {
        SaltString::from_b64(&salt)
            .map_err(|e| format!("Invalid salt: {}", e))?
    } else {
        SaltString::generate(&mut OsRng)
    };
    
    let password_hash = Pbkdf2
        .hash_password(request.password.as_bytes(), &salt_string)
        .map_err(|e| format!("Failed to hash password: {}", e))?;
    
    Ok(PasswordHashResponse {
        hash: password_hash.to_string(),
        salt: salt_string.to_string(),
    })
}

// PBKDF2 Verify
#[tauri::command]
fn verify_pbkdf2(request: PasswordVerifyRequest) -> Result<PasswordVerifyResponse, String> {
    let parsed_hash = PasswordHash::new(&request.hash)
        .map_err(|e| format!("Invalid hash format: {}", e))?;
    
    let valid = Pbkdf2
        .verify_password(request.password.as_bytes(), &parsed_hash)
        .is_ok();
    
    Ok(PasswordVerifyResponse { valid })
}

// Scrypt Hash
#[tauri::command]
fn hash_scrypt(request: PasswordHashRequest) -> Result<PasswordHashResponse, String> {
    let salt_string = if let Some(salt) = request.salt {
        ScryptSaltString::from_b64(&salt)
            .map_err(|e| format!("Invalid salt: {}", e))?
    } else {
        ScryptSaltString::generate(&mut OsRng)
    };
    
    let password_hash = Scrypt
        .hash_password(request.password.as_bytes(), &salt_string)
        .map_err(|e| format!("Failed to hash password: {}", e))?;
    
    Ok(PasswordHashResponse {
        hash: password_hash.to_string(),
        salt: salt_string.to_string(),
    })
}

// Scrypt Verify
#[tauri::command]
fn verify_scrypt(request: PasswordVerifyRequest) -> Result<PasswordVerifyResponse, String> {
    let parsed_hash = ScryptPasswordHash::new(&request.hash)
        .map_err(|e| format!("Invalid hash format: {}", e))?;
    
    let valid = Scrypt
        .verify_password(request.password.as_bytes(), &parsed_hash)
        .is_ok();
    
    Ok(PasswordVerifyResponse { valid })
}

// Bcrypt Hash
#[tauri::command]
fn hash_bcrypt(request: PasswordHashRequest) -> Result<PasswordHashResponse, String> {
    let cost = request.iterations.unwrap_or(12) as u32;
    
    let hash = bcrypt::hash(&request.password, cost)
        .map_err(|e| format!("Failed to hash password: {}", e))?;
    
    // Bcrypt hash includes the salt
    Ok(PasswordHashResponse {
        hash: hash.clone(),
        salt: "included_in_hash".to_string(),
    })
}

// Bcrypt Verify
#[tauri::command]
fn verify_bcrypt(request: PasswordVerifyRequest) -> Result<PasswordVerifyResponse, String> {
    let valid = bcrypt::verify(&request.password, &request.hash)
        .map_err(|e| format!("Failed to verify password: {}", e))?;
    
    Ok(PasswordVerifyResponse { valid })
}

// Argon2 Hash
#[tauri::command]
fn hash_argon2(request: PasswordHashRequest) -> Result<PasswordHashResponse, String> {
    let salt_string = if let Some(salt) = request.salt {
        Argon2SaltString::from_b64(&salt)
            .map_err(|e| format!("Invalid salt: {}", e))?
    } else {
        Argon2SaltString::generate(&mut OsRng)
    };
    
    // Build Argon2 params - use default and customize if needed
    let params = if request.memory.is_some() || request.argon2_iterations.is_some() || request.parallelism.is_some() {
        let mut builder = ParamsBuilder::new();
        if let Some(m) = request.memory {
            builder.m_cost(m);
        }
        if let Some(t) = request.argon2_iterations {
            builder.t_cost(t);
        }
        if let Some(p) = request.parallelism {
            builder.p_cost(p);
        }
        builder.build().map_err(|e| format!("Failed to build params: {}", e))?
    } else {
        argon2::Params::default()
    };
    
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );
    
    let password_hash = argon2
        .hash_password(request.password.as_bytes(), &salt_string)
        .map_err(|e| format!("Failed to hash password: {}", e))?;
    
    Ok(PasswordHashResponse {
        hash: password_hash.to_string(),
        salt: salt_string.to_string(),
    })
}

// Argon2 Verify
#[tauri::command]
fn verify_argon2(request: PasswordVerifyRequest) -> Result<PasswordVerifyResponse, String> {
    let parsed_hash = Argon2PasswordHash::new(&request.hash)
        .map_err(|e| format!("Invalid hash format: {}", e))?;
    
    let argon2 = Argon2::default();
    let valid = argon2
        .verify_password(request.password.as_bytes(), &parsed_hash)
        .is_ok();
    
    Ok(PasswordVerifyResponse { valid })
}

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            greet, 
            http_request, 
            generate_dsa_keypair, 
            dsa_sign, 
            dsa_verify,
            hash_pbkdf2,
            verify_pbkdf2,
            hash_scrypt,
            verify_scrypt,
            hash_bcrypt,
            verify_bcrypt,
            hash_argon2,
            verify_argon2
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
