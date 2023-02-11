use std::str;

use serde::{Deserialize, Serialize};
use worker::*;
use worker::wasm_bindgen::JsValue;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        .get("/", |_, _| Response::ok("OK"))
        .get_async("/redirect/:key", |_, ctx| async move {
            if let Some(key) = ctx.param("key") {
                let db: D1Database = ctx.env.d1("DB")?;

                let statement = db
                    .prepare("SELECT long_url FROM grv_links WHERE key =?")
                    .bind(&[JsValue::from(key)])?;

                let results: Option<String> = statement.first(Some("long_url")).await?;

                return match results {
                    None => {
                        Response::error("URL Unknown", 404)
                    }
                    Some(url) => {
                        let d1result = increment_link_clicks(key, &db).await?;
                        if !d1result.success() {
                            console_log!("Error while updating clicks for link {key:}")
                        }
                        Response::redirect(Url::parse(url.as_str())?)
                    }
                };
            }
            Response::error("Key Missing", 400)
        })
        .get_async("/list", |_, ctx| async move {
            let db: D1Database = ctx.env.d1("DB")?;

            let statement = db.prepare("SELECT * FROM grv_links WHERE unlisted = 0");

            let d1_results = statement.all().await?;
            let link_results = d1_results.results::<Link>()?;

            Response::ok(serde_json::to_string(link_results.as_slice())?)
        })
        .get_async("/info/:key", |_, ctx| async move {
            if let Some(key) = ctx.param("key") {
                let db: D1Database = ctx.env.d1("DB")?;

                let statement = db
                    .prepare("SELECT * FROM grv_links WHERE key = ?")
                    .bind(&[JsValue::from(key)])?;

                let results = statement.all().await?;

                let result = results.results::<Link>()?;

                return match result.get(0) {
                    None => return Response::error("Key not found", 404),
                    Some(url) => Response::ok(serde_json::to_string(url)?),
                };
            }
            Response::error("Key Missing", 400)
        })
        .put_async("/", |mut req, ctx| async move {
            if let Some(err) = check_apikey(&req, &ctx) {
                return err;
            }

            let buf = req.bytes().await?;

            if let Ok(data) = str::from_utf8(buf.as_slice()) {
                let result: Link = serde_json::from_str(data)?;

                let db: D1Database = ctx.env.d1("DB")?;

                let statement = db
                    .prepare("INSERT INTO grv_links(`key`, `long_url`, `clicks`, `unlisted`) VALUES (?,?,?,?)")
                    .bind(&[
                        JsValue::from(result.key.as_str()),
                        JsValue::from(result.long_url.as_str()),
                        JsValue::from(result.clicks.to_string()),
                        JsValue::from(result.unlisted.unwrap())])?;

                return match statement.run().await {
                    Ok(_) => Response::ok("OK"),
                    Err(err) => Response::error(format!("Database error! {err:?}"), 500)
                };
            }

            Response::error("Invalid data send", 500)
        })
        .patch_async("/", |mut req, ctx| async move {
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
                        JsValue::from(result.clicks.to_string()),
                        JsValue::from(result.unlisted.unwrap()),
                        JsValue::from(result.long_url.as_str()),
                        JsValue::from(result.clicks.to_string()),
                        JsValue::from(result.unlisted.unwrap())])?;

                return match statement.run().await {
                    Ok(_) => Response::ok("OK"),
                    Err(err) => Response::error(format!("Database error! {err:?}"), 500)
                };
            }

            Response::error("Invalid data send", 500)
        })
        .delete_async("/:key", |req, ctx| async move {
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
                    Response::ok("Link deleted")
                } else {
                    Response::error("Can not delete link", 500)
                };
            }
            Response::error("Key Missing", 400)
        })
        .run(req, env)
        .await
}

fn check_apikey(req: &Request, ctx: &RouteContext<()>) -> Option<Result<Response>> {
    let secret_apikey = ctx.secret("APIKEY");
    if secret_apikey.is_err() {
        return Some(Response::error("Unable to get APIKey", 500));
    }
    let header_apikey = req.headers().get("APIKEY");
    if header_apikey.is_err() {
        return Some(Response::error("APIKEY missing", 401));
    }

    match header_apikey.unwrap() {
        None => Some(Response::error("APIKEY missing", 401)),
        Some(option_header) => {
            if secret_apikey.unwrap().to_string().ne(&option_header) {
                return Some(Response::error("APIKEY invalid", 401));
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
    clicks: usize,
    #[serde(skip_serializing)]
    unlisted: Option<u8>
}
