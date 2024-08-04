use std::collections::HashMap;
use std::str;

use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::*;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        .get("/", |_, _| build_response("OK", 200))
        .get_async("/redirect/:key", redirect)
        .get_async("/list", list_links)
        .get_async("/info/:key", link_info)
        .put_async("/", add_link)
        .patch_async("/", patch_link)
        .delete_async("/:key", delete_link)
        .run(req, env)
        .await
}

async fn redirect(_: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Some(key) = ctx.param("key") {
        let db: D1Database = ctx.env.d1("DB")?;

        let statement = db
            .prepare("SELECT long_url FROM grv_links WHERE key =?")
            .bind(&[JsValue::from(key)])?;

        let results: Option<String> = statement.first(Some("long_url")).await?;

        return match results {
            None => build_response("URL Unknown", 404),
            Some(url) => {
                let d1result = increment_link_clicks(key, &db).await?;
                if !d1result.success() {
                    console_log!("Error while updating clicks for link {key:}")
                }
                Response::redirect(Url::parse(url.as_str())?)
            }
        };
    }
    build_response("Key Missing", 400)
}

async fn list_links(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let db: D1Database = ctx.env.d1("DB")?;
    let hash_query: HashMap<_, _> = req.url()?.query_pairs().into_owned().collect();

    let statement = if hash_query
        .get("show_unlisted")
        .unwrap_or(&"false".to_string())
        .eq("true")
    {
        if let Some(err) = check_apikey(&req, &ctx) {
            return err;
        }
        db.prepare("SELECT * FROM grv_links")
    } else {
        db.prepare("SELECT key, long_url FROM grv_links WHERE unlisted = 0")
    };

    let d1_results = statement.all().await?;
    let link_results = d1_results.results::<Link>()?;

    build_response(
        serde_json::to_string(link_results.as_slice())?.as_str(),
        200,
    )
}

async fn link_info(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Some(key) = ctx.param("key") {
        let db: D1Database = ctx.env.d1("DB")?;

        let statement = if check_apikey(&req, &ctx).is_none() {
            db.prepare("SELECT * FROM grv_links WHERE key = ?")
                .bind(&[JsValue::from(key)])?
        } else {
            db.prepare("SELECT key, long_url FROM grv_links WHERE key = ?")
                .bind(&[JsValue::from(key)])?
        };

        let results = statement.all().await?;

        let result = results.results::<Link>()?;

        return match result.get(0) {
            None => return build_response("Key not found", 404),
            Some(url) => build_response(serde_json::to_string(url)?.as_str(), 200),
        };
    }
    build_response("Key Missing", 400)
}

async fn add_link(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Some(err) = check_apikey(&req, &ctx) {
        return err;
    }

    let buf = req.bytes().await?;

    if let Ok(data) = str::from_utf8(buf.as_slice()) {
        let result: Link = serde_json::from_str(data)?;

        let db: D1Database = ctx.env.d1("DB")?;

        let statement = db
            .prepare(
                "INSERT INTO grv_links(`key`, `long_url`, `clicks`, `unlisted`) VALUES (?,?,?,?)",
            )
            .bind(&[
                JsValue::from(result.key.as_str()),
                JsValue::from(result.long_url.as_str()),
                JsValue::from(result.clicks.unwrap_or_default().to_string()),
                JsValue::from(result.unlisted.unwrap_or_default()),
            ])?;

        return match statement.run().await {
            Ok(_) => build_response("OK", 200),
            Err(_) => build_response("Database error!", 500),
        };
    }

    build_response("Invalid data send", 500)
}

async fn delete_link(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Some(err) = check_apikey(&req, &ctx) {
        return err;
    }

    if let Some(key) = ctx.param("key") {
        let db: D1Database = ctx.env.d1("DB")?;

        let statement = db
            .prepare("DELETE FROM grv_links WHERE key = ? ")
            .bind(&[JsValue::from(key)])?;

        let results = statement.run().await?;
        return if results.success() {
            build_response("Link deleted", 200)
        } else {
            build_response("Can not delete link", 500)
        };
    }
    build_response("Key Missing", 400)
}

async fn patch_link(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Some(err) = check_apikey(&req, &ctx) {
        return err;
    }

    let buf = req.bytes().await?;

    if let Ok(data) = str::from_utf8(buf.as_slice()) {
        let result: Link = serde_json::from_str(data)?;

        let db: D1Database = ctx.env.d1("DB")?;

        let statement = db
            .prepare("INSERT INTO grv_links(`key`, `long_url`, `clicks`, `unlisted`) VALUES (?,?,?,?) ON CONFLICT(`key`) DO UPDATE SET `long_url` = ?, `clicks` = ?, `unlisted` = ?")
            .bind(&[
                JsValue::from(result.key.as_str()),
                JsValue::from(result.long_url.as_str()),
                JsValue::from(result.clicks.unwrap_or_default()),
                JsValue::from(result.unlisted.unwrap_or_default()),
                JsValue::from(result.long_url.as_str()),
                JsValue::from(result.clicks.unwrap_or_default()),
                JsValue::from(result.unlisted.unwrap_or_default())])?;

        return match statement.run().await {
            Ok(_) => build_response("OK", 200),
            Err(_) => build_response("Database error!", 500),
        };
    }

    build_response("Invalid data send", 500)
}

fn build_headers(status_code: u16) -> Result<Headers> {
    let mut headers = Headers::new();
    if (200..=299).contains(&status_code) {
        headers.set("Content-Type", "application/json")?;
    }
    Ok(headers)
}

fn build_response(msg: &str, status_code: u16) -> Result<Response> {
    Response::ok(msg)?
        .with_headers(build_headers(status_code)?)
        .with_status(status_code)
        .with_cors(&Cors::new().with_origins(vec!["*"]))
}

fn check_apikey(req: &Request, ctx: &RouteContext<()>) -> Option<Result<Response>> {
    let secret_apikey = ctx.secret("APIKEY");
    if secret_apikey.is_err() {
        return Some(build_response("Unable to get APIKey", 500));
    }
    let header_apikey = req.headers().get("APIKEY");
    if header_apikey.is_err() {
        return Some(build_response("APIKEY missing", 401));
    }

    match header_apikey.unwrap() {
        None => Some(build_response("APIKEY missing", 401)),
        Some(option_header) => {
            if secret_apikey.unwrap().to_string().ne(&option_header) {
                return Some(build_response("APIKEY invalid", 401));
            }
            None
        }
    }
}

async fn increment_link_clicks(key: &String, database: &D1Database) -> Result<D1Result> {
    let statement = database
        .prepare("UPDATE grv_links SET `clicks`=`clicks` + 1 WHERE `key` = ?")
        .bind(&[JsValue::from(key)])?;

    statement.run().await
}

#[derive(Debug, Deserialize, Serialize)]
struct Link {
    key: String,
    long_url: String,
    #[serde(skip_serializing_if="Option::is_none")]
    clicks: Option<usize>,
    #[serde(skip_serializing_if="Option::is_none")]
    unlisted: Option<u8>,
}
