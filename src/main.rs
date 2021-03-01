use anyhow::{anyhow, Result};
use chrono::Utc;
use fastly::http::{header, Method, StatusCode};
use fastly::{mime, Error, Request, Response};
use hmac_sha256::HMAC;
use std::collections::HashMap;

/// The name of a backend server associated with this service.
///
/// This should be changed to match the name of your own backend. See the the `Hosts` section of
/// the Fastly WASM service UI for more information.
const BACKEND_NAME: &str = "noguxun.github.io";
const SECRET_KEY: &str = "this_is_your_secret_key";

/// The entry point for your application.
///
/// This function is triggered when your service receives a client request. It could be used to
/// route based on the request properties (such as method or path), send the request to a backend,
/// make completely new requests, and/or generate synthetic responses.
///
/// If `main` returns an error, a 500 error response will be delivered to the client.
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
        // If request is to the `/` path, send a default response.
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

        // If request is to a path starting with `/other/`...
        path if path.starts_with("/img/") => {
            if let Err(e) = auth_check(&req) {
                Ok(Response::from_status(StatusCode::FORBIDDEN)
                    .with_body_str(&format!("Auth failed: {}", e)))
            } else {
                Ok(req.send(BACKEND_NAME)?)
            }
        }

        // Catch all other requests and return a 404.
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
