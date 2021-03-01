use anyhow::{anyhow, Result};
use chrono::Utc;
use fastly::http::{header, Method, StatusCode};
use fastly::{mime, Error, Request, Response};
use hmac_sha256::HMAC;
use std::collections::HashMap;

const BACKEND_NAME: &str = "noguxun.github.io";
const SECRET_KEY: &str = "this_is_your_secret_key";

#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    // Make any desired changes to the client request.
    req.set_header(header::HOST, "example.com");

    // Filter request methods...
    match req.get_method() {
        // Allow GET and HEAD requests.
        &Method::GET | &Method::HEAD => (),

        // Accept PURGE requests; it does not matter to which backend they are sent.
        m if m == "PURGE" => return Ok(req.send(BACKEND_NAME)?),

        // Deny anything else.
        _ => {
            return Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
                .with_header(header::ALLOW, "GET, HEAD")
                .with_body_str("This method is not allowed\n"))
        }
    };

    println!(
        "{} {} {}",
        req.get_method(),
        req.get_url_str(),
        ip = req
            .get_client_ip_addr()
            .ok_or_else(|| anyhow!("client ip error"))?
    );

    // Pattern match on the path.
    match req.get_path() {
        "/" => {
            let ip = req
                .get_client_ip_addr()
                .ok_or_else(|| anyhow!("client ip error"))?
                .to_string();
            let page_body = sign_page(&ip, include_str!("index.html"));

            Ok(Response::from_status(StatusCode::OK)
                .with_content_type(mime::TEXT_HTML_UTF_8)
                .with_body(page_body))
        }

        path if path.starts_with("/tela") => {
            let ip = req
                .get_client_ip_addr()
                .ok_or_else(|| anyhow!("client ip error"))?
                .to_string();

            req.set_path("/demo/protected-media/index.html");

            let resp = req.send(BACKEND_NAME)?;

            let body = resp.into_body_str();

            let body_signed = sign_page(&ip, &body);

            Ok(Response::from_status(StatusCode::OK)
                .with_content_type(mime::TEXT_HTML_UTF_8)
                .with_body(body_signed))
        }

        path if path.starts_with("/img/") => {
            if let Err(e) = auth_check(&req) {
                Ok(Response::from_status(StatusCode::FORBIDDEN)
                    .with_body_str(&format!("Auth failed: {}", e)))
            } else {
                Ok(req.send(BACKEND_NAME)?)
            }
        }

        _ => Ok(req.send(BACKEND_NAME)?),
    }
}

fn auth_check(req: &Request) -> Result<()> {
    let params: HashMap<String, String> = req.get_query()?;

    let timestamp = params.get("t").ok_or_else(|| anyhow!("No timestamp"))?;
    let signature = params.get("sig").ok_or_else(|| anyhow!("No signature"))?;

    let now = Utc::now().timestamp();
    if now > timestamp.parse::<i64>()? + 10 {
        return Err(anyhow!("expired"));
    }

    let ip = req
        .get_client_ip_addr()
        .ok_or_else(|| anyhow!("client ip error"))?
        .to_string();
    let expected_sig = get_signature(timestamp, &ip);

    println!("{} {} {} {}", timestamp, ip, signature, expected_sig);

    if &expected_sig == signature {
        Ok(())
    } else {
        Err(anyhow!("signature not match"))
    }
}

fn get_signature(timestamp: &str, ip: &str) -> String {
    let string_to_sign = format!("{}_{}", timestamp, ip);

    let signature_binary = HMAC::mac(string_to_sign.as_bytes(), SECRET_KEY.as_bytes());

    base64::encode_config(signature_binary, base64::URL_SAFE_NO_PAD)
}

fn sign_page(ip: &str, body: &str) -> String {
    let timestamp = format!("{}", Utc::now().timestamp());

    let signature = get_signature(&timestamp, ip);

    let qs_signature = format!(".jpeg?t={}&sig={}", timestamp, signature);

    body.replace(".jpeg", &qs_signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test1() {
        println!("{}", sign_page("127.0.0.1", include_str!("index.html")));
    }
}
