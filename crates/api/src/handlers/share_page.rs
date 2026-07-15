use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
};
use sqlx::Row;
use uuid::Uuid;

use crate::{errors::ApiError, state::AppState};

/// Escapes HTML special characters to prevent XSS
fn escape_html(s: &str) -> String {
    s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#x27;")
}

/// Simple token bucket rate limiter: 10 requests per minute per IP
fn check_rate_limit(
    state: &AppState,
    client_ip: &str,
) -> Result<(), ApiError> {
    const MAX_REQUESTS: i32 = 10;
    const WINDOW_SECS: u64 = 60;
    
    let now = std::time::Instant::now();
    let mut limiter = state.rate_limiter.lock().map_err(|_| ApiError::internal())?;
    
    match limiter.get_mut(client_ip) {
        Some((count, last_check)) => {
            // If window has expired, reset the counter
            if last_check.elapsed().as_secs() > WINDOW_SECS {
                *count = 1;
                *last_check = now;
                Ok(())
            } else if *count < MAX_REQUESTS {
                *count += 1;
                Ok(())
            } else {
                Err(ApiError::rate_limited())
            }
        }
        None => {
            limiter.insert(client_ip.to_string(), (1, now));
            Ok(())
        }
    }
}
/// GET /v/:pass_number
/// Serves a bare-minimum, beautifully styled server-rendered HTML page
/// containing the visitor pass details and its QR code for native mobile sharing.
pub async fn share_page(
    State(state): State<AppState>,
    Path(pass_number): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    // Extract client IP from headers (X-Forwarded-For or connection IP)
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim())
        .unwrap_or("127.0.0.1")
        .to_string();
    
    // Check rate limit: 10 requests per minute per IP
    check_rate_limit(&state, &client_ip)?;
    
    // Public lookup: does not require OrgContext (anyone with the link can view)
    let pass = state
        .passes
        .find_by_pass_number_public(&pass_number)
        .await?;

    let valid_from_formatted = pass.valid_from.format("%d %b %Y, %I:%M %p").to_string();
    let valid_until_formatted = pass.valid_until.format("%d %b %Y, %I:%M %p").to_string();

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Visitor Pass - {visitor_name}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js" integrity="sha384-N5WuhvjBh1zV9uep0fI6BXY6Gtg1b2F/G+3xP7Uo1y3X2sP1P5L7c5Y6T+Q2F6r+" crossorigin="anonymous"></script>
    <style>
        :root {{
            --bg-primary: #0b0f19;
            --bg-card: #151b2c;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent: #3b82f6;
            --accent-glow: rgba(59, 130, 246, 0.15);
            --border: #222c42;
            --success: #10b981;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: 'Plus Jakarta Sans', sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }}

        .pass-container {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 24px;
            width: 100%;
            max-width: 440px;
            overflow: hidden;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3), 0 0 80px var(--accent-glow);
        }}

        .pass-header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            padding: 24px;
            text-align: center;
            border-bottom: 1px dashed var(--border);
            position: relative;
        }}

        .pass-header::before, .pass-header::after {{
            content: '';
            position: absolute;
            bottom: -10px;
            width: 20px;
            height: 20px;
            background-color: var(--bg-primary);
            border-radius: 50%;
        }}
        .pass-header::before {{ left: -10px; }}
        .pass-header::after {{ right: -10px; }}

        .logo {{
            font-size: 20px;
            font-weight: 700;
            letter-spacing: -0.5px;
            color: var(--text-primary);
            margin-bottom: 4px;
        }}
        
        .logo span {{
            color: var(--accent);
        }}

        .org-name {{
            font-size: 13px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .pass-body {{
            padding: 32px 24px 24px 24px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}

        .qr-wrapper {{
            background-color: #ffffff;
            padding: 16px;
            border-radius: 20px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
            margin-bottom: 24px;
            display: flex;
            justify-content: center;
            align-items: center;
        }}

        #qrcode {{
            width: 200px;
            height: 200px;
        }}

        .pass-number {{
            font-family: monospace;
            font-size: 18px;
            font-weight: 700;
            color: var(--accent);
            background-color: rgba(59, 130, 246, 0.1);
            padding: 6px 16px;
            border-radius: 99px;
            margin-bottom: 24px;
            letter-spacing: 1px;
            border: 1px solid rgba(59, 130, 246, 0.2);
        }}

        .visitor-name {{
            font-size: 22px;
            font-weight: 700;
            margin-bottom: 6px;
            text-align: center;
        }}

        .purpose {{
            font-size: 14px;
            color: var(--text-secondary);
            margin-bottom: 24px;
            background-color: rgba(255, 255, 255, 0.03);
            padding: 4px 12px;
            border-radius: 6px;
        }}

        .details-grid {{
            width: 100%;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            border-top: 1px solid var(--border);
            padding-top: 24px;
            margin-bottom: 20px;
        }}

        .detail-item {{
            display: flex;
            flex-direction: column;
        }}

        .detail-label {{
            font-size: 11px;
            color: var(--text-secondary);
            text-transform: uppercase;
            margin-bottom: 4px;
            letter-spacing: 0.5px;
        }}

        .detail-value {{
            font-size: 14px;
            font-weight: 600;
        }}

        .status-badge {{
            display: inline-flex;
            align-items: center;
            font-size: 12px;
            font-weight: 600;
            color: var(--success);
            gap: 6px;
        }}

        .status-dot {{
            width: 8px;
            height: 8px;
            background-color: var(--success);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--success);
        }}

        .footer-note {{
            font-size: 12px;
            color: var(--text-secondary);
            text-align: center;
            margin-top: 16px;
            width: 100%;
            border-top: 1px solid var(--border);
            padding-top: 16px;
        }}
    </style>
</head>
<body>
    <div class="pass-container">
        <div class="pass-header">
            <div class="logo">Visitor<span>Pass</span></div>
            <div class="org-name">Access Invitation</div>
        </div>
        <div class="pass-body">
            <div class="qr-wrapper">
                <div id="qrcode"></div>
            </div>
            <div class="pass-number">{pass_number}</div>
            <div class="visitor-name">{visitor_name}</div>
            <div class="purpose">Purpose: {purpose}</div>

            <div class="details-grid">
                <div class="detail-item" style="grid-column: span 2;">
                    <span class="detail-label">Validity Window</span>
                    <span class="detail-value" style="font-size: 13px;">{valid_from} &rarr; {valid_until}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Vehicle</span>
                    <span class="detail-value">{vehicle}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Status</span>
                    <span class="status-badge"><span class="status-dot"></span>{status}</span>
                </div>
            </div>

            <div class="footer-note">
                Please present this QR code at the security gate for scanning.
            </div>
        </div>
    </div>

    <script>
        // Generate QR code using cdn library
        try {{
            var qr = qrcode(0, 'M');
            qr.addData('{qr_payload}');
            qr.make();
            document.getElementById('qrcode').innerHTML = qr.createImgTag(5);
        }} catch (e) {{
            console.error('Failed to render QR Code', e);
        }}
    </script>
</body>
</html>"#,
        visitor_name = escape_html(&pass.visitor_name),
        pass_number = escape_html(pass.pass_number.as_str()),
        purpose = escape_html(&pass.purpose),
        valid_from = valid_from_formatted,
        valid_until = valid_until_formatted,
        vehicle = escape_html(&pass.vehicle_number.unwrap_or_else(|| "None".to_string())),
        status = format!("{:?}", pass.status).to_uppercase(),
        qr_payload = escape_html(&pass.qr_payload)
    );

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, HeaderValue::from_static("text/html"))],
        html,
    ))
}
