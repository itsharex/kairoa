use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose};

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
        .invoke_handler(tauri::generate_handler![greet, http_request])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
