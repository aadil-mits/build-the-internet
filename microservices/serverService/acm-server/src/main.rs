use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{rejection::JsonRejection, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

struct User {
    id: u64,
    hash: String,
}

#[derive(Default)]
struct AppState {
    users: RwLock<HashMap<String, User>>,
    sessions: RwLock<HashMap<String, (u64, String)>>, // token -> (user_id, username)
    next_id: AtomicU64,
}

type Shared = Arc<AppState>;

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

async fn register(
    State(st): State<Shared>,
    payload: Result<Json<Credentials>, JsonRejection>,
) -> Response {
    let Ok(Json(c)) = payload else {
        return err(StatusCode::BAD_REQUEST, "Invalid payload");
    };
    if c.username.is_empty() || c.password.is_empty() {
        return err(StatusCode::BAD_REQUEST, "Invalid payload");
    }
    if st.users.read().unwrap().contains_key(&c.username) {
        return err(StatusCode::BAD_REQUEST, "Username already exists");
    }

    // Argon2 is CPU-heavy; keep it off the async workers.
    let pw = c.password;
    let hash = tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(pw.as_bytes(), &salt)
            .map(|h| h.to_string())
    })
    .await;
    let Ok(Ok(hash)) = hash else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
    };

    let mut users = st.users.write().unwrap();
    if users.contains_key(&c.username) {
        return err(StatusCode::BAD_REQUEST, "Username already exists");
    }
    let id = 101 + st.next_id.fetch_add(1, Ordering::Relaxed);
    users.insert(c.username, User { id, hash });
    (
        StatusCode::CREATED,
        Json(json!({ "status": "ok", "message": "User registered successfully" })),
    )
        .into_response()
}

async fn login(
    State(st): State<Shared>,
    payload: Result<Json<Credentials>, JsonRejection>,
) -> Response {
    let bad = || err(StatusCode::UNAUTHORIZED, "Invalid username or password");
    let Ok(Json(c)) = payload else { return bad() };

    let found = st
        .users
        .read()
        .unwrap()
        .get(&c.username)
        .map(|u| (u.id, u.hash.clone()));
    let Some((id, hash)) = found else { return bad() };

    let pw = c.password;
    let ok = tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash)
            .map(|p| Argon2::default().verify_password(pw.as_bytes(), &p).is_ok())
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false);
    if !ok {
        return bad();
    }

    let token = uuid::Uuid::new_v4().simple().to_string();
    st.sessions
        .write()
        .unwrap()
        .insert(token.clone(), (id, c.username));

    (
        StatusCode::OK,
        [(
            header::SET_COOKIE,
            format!("session_id={token}; Path=/; HttpOnly; SameSite=Lax"),
        )],
        Json(json!({ "status": "ok", "message": "Login successful" })),
    )
        .into_response()
}

fn session_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == "session_id")
        .map(|(_, v)| v)
}

async fn whoami(State(st): State<Shared>, headers: HeaderMap) -> Response {
    let session = session_token(&headers)
        .and_then(|t| st.sessions.read().unwrap().get(t).cloned());
    match session {
        Some((id, username)) => Json(json!({
            "status": "ok",
            "user_id": id,
            "username": username
        }))
        .into_response(),
        None => err(
            StatusCode::UNAUTHORIZED,
            "Unauthorized - Invalid or missing session cookie",
        ),
    }
}

#[tokio::main]
async fn main() {
    let state: Shared = Arc::default();
    let app = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/whoami", get(whoami))
        .with_state(state);

    let addr = std::env::var("ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("acm-server listening on {addr}");
    axum::serve(listener, app).await.unwrap();
}
