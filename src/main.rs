mod awsv4;
mod config;
mod cookies;
mod idp;
mod jwt;
mod pkce;
mod responses;

use std::collections::{HashMap, HashSet};
use std::{env};
use chrono::Utc;
use config::Config;
use crate::awsv4::hash;
use fastly::http::header::{AUTHORIZATION};
use fastly::{Backend, Body, SecretStore, Error, Request, Response};
use idp::{AuthCodePayload, AuthorizeResponse, CallbackQueryParameters, ExchangePayload};
use jwt::{validate_token_rs256, NonceToken};
use jwt_simple::claims::{JWTClaims, NoCustomClaims};
use lazy_static::lazy_static;
use pkce::{rand_chars, Pkce};
use regex::Regex;
use serde::{Deserialize, Serialize};

// Fastly objects
const FASTLY_SECRET_STORE: &str = "devweek2023-demo";
const B2_BACKEND: &str = "backend";
const AUTH_SERVER_BACKEND: &str = "idp";

const MAX_LEN_APPLICATION_KEY_ID: usize = 25;
const MAX_LEN_APPLICATION_KEY: usize = 31;

// These paths will be served with no authentication
const PUBLIC_PATHS: &[&str] = &[
    "/favicon.ico",
    "/logged-out.html"
];

// Public home page
const PUBLIC_HOME: &str = "/public.html";

// Authenticated home page
const PRIVATE_HOME: &str = "/index.html";

// Logged out page
const LOGOUT_INTERSTITIAL: &str = "/logged-out.html";

// Login page
const LOGIN: &str = "/login";

// Regex for extracting region from endpoint of form <bucketname>.s3.<region>.backblazeb2.com
lazy_static! {
    static ref REGION_REGEX: Regex = Regex::new(r"^[[:alnum:]\-]+\.s3\.([[:alnum:]\-]+)\.backblazeb2\.com$").unwrap();
}

// Define a custom claim set containing just the "groups" claim
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct GroupsClaim {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<HashSet<String>>,
}

#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    // Initialize logging to B2, copying to stdout so that log tailing works also
    log_fastly::Logger::builder()
        .max_level(log::LevelFilter::Debug)
        .default_endpoint("devweek2023-logs")
        .echo_stdout(true)
        .init();

    // Generate backtraces on errors (supposedly!)
    env::set_var("RUST_BACKTRACE", "full");

    // Log service version
    log::info!(
        "FASTLY_SERVICE_VERSION: {}",
        env::var("FASTLY_SERVICE_VERSION").unwrap_or_else(|_| String::new())
    );

    // Build the base URL, e.g. "https://devweek2023-demo.edgecompute.app"
    // No trailing slash!
    let base_uri = format!(
        "https://{}",
        req.get_url().host_str().unwrap()
    );

    // Load the service configuration, and the OpenID discovery and token signature metadata.
    let settings = Config::load();

    // Parse the Cookie header.
    let cookie_header = req.remove_header_str("cookie").unwrap_or_default();
    let cookie = cookies::parse(&cookie_header);

    // Build the OAuth 2.0 redirect URL.
    let redirect_uri = format!(
        "{}{}",
        base_uri,
        settings.config.callback_path
    );

    // If the path matches the redirect URL path, continue the OAuth 2.0 authorization code flow.
    if req.get_url_str().starts_with(&redirect_uri) {
        return handle_authorization_code(&mut req, &settings, &cookie, &redirect_uri);
    }

    // Serve open paths without authentication
    if PUBLIC_PATHS.contains(&req.get_path()) {
        return send_to_backend(req, true);
    }

    // Verify any tokens stored as a result of a complete OAuth 2.0 authorization code flow.
    if let (Some(access_token), Some(id_token)) =
        (cookie.get("access_token"), cookie.get("id_token"))
    {
        // If the path matches the logout URL path, redirect for logout.
        // Do this after retrieving cookies, so we have the id_token, but
        // before validating cookies so we can clear them even if we think
        // they are not valid!
        if req.get_path() == "/logout" {
            return handle_logout(base_uri, &settings, id_token);
        }

        if req.get_path() == "/slo/logout" {
            return handle_slo();
        }

        let claims = match validate_tokens(&settings, access_token, id_token) {
            Ok(claims) => claims,
            Err(response) => {
                return Ok(response);
            },
        };

        log::info!("Authentication successful!");
        log::info!("ID token: {}", id_token);
        log::info!("Access token: {}", access_token);
        log::info!("Parsed claims: {}", serde_json::to_string_pretty(&claims).unwrap());

        if req.get_path() == "/" {
            req.set_path(PRIVATE_HOME);
        };

        return match authorize_request(&mut req, claims) {
            // Sign and send the request to the origin backend.
            Ok(_) => send_to_backend(req, false),
            Err(response) => Ok(response)
        };
    }

    // Public home page
    if req.get_path() == "/" {
        req.set_path(PUBLIC_HOME);
        return send_to_backend(req, false);
    }

    // Logout without cookie(s) - just redirect home
    if req.get_path() == "/logout" {
        log::debug!("Already logged out - redirecting home");
        return Ok(responses::home());
    }

    // SLO without cookie(s) - just return OK
    if req.get_path() == "/slo/logout" {
        log::debug!("Already logged out - responding with 200 OK");
        return Ok(responses::ok());
    }

    // LOGIN wants to redirect to "/"
    // Everything redirects to the requested path
    let target_path = match req.get_path() == LOGIN {
        true => "/".to_string(),
        false => req.get_path().to_string(),
    };

    // Start the OAuth 2.0 authorization code flow.
    start_authorization_flow(&mut req, &settings, &redirect_uri, target_path)
}

fn start_authorization_flow(req: &mut Request, settings: &Config, redirect_uri: &String, target_path: String) -> Result<Response, Error> {
    // Generate the Proof Key for Code Exchange (PKCE) code verifier and code challenge.
    let pkce = Pkce::new(settings.config.code_challenge_method);

    // Generate the OAuth 2.0 state parameter, used to prevent CSRF attacks,
    // and store the original request path and query string.
    let state = {
        let (sep, query) = match req.get_query_str() {
            Some(q) => ("?", q),
            None => ("", ""),
        };
        let rand_chars = rand_chars(settings.config.state_parameter_length);
        format!("{}{}{}{}", target_path, sep, query, rand_chars)
    };

    // Generate the OpenID Connect nonce, used to mitigate replay attacks.
    // This is a random value with a twist: in is a time limited token (JWT)
    // that encodes the nonce and the state within its claims.
    let (state_and_nonce, nonce) =
        NonceToken::new(settings.config.nonce_secret).generate_from_state(&state);

    // Build the authorization request.
    let authorize_req = Request::get(settings.openid_configuration.authorization_endpoint)
        .with_query(&AuthCodePayload {
            client_id: settings.config.client_id,
            code_challenge: &pkce.code_challenge,
            code_challenge_method: settings.config.code_challenge_method,
            redirect_uri: &redirect_uri,
            response_type: "code",
            scope: &settings.config.scope,
            state: &state_and_nonce,
            nonce: &nonce,
        })
        .unwrap();
    log::info!("Redirecting for login: {}", authorize_req.get_url_str());

    // Redirect to the Identity Provider's login and authorization prompt.
    Ok(responses::temporary_redirect(
        authorize_req.get_url_str(),
        cookies::expired("access_token"),
        cookies::expired("id_token"),
        cookies::session("code_verifier", &pkce.code_verifier),
        cookies::session("state", &state),
    ))
}

fn authorize_request(req: &mut Request, claims: JWTClaims<GroupsClaim>) -> Result<(), Response> {
    let segments: Vec<&str> = req.get_path().splitn(3, "/").collect();

    // Iff there is a directory:
    // * segments will have 3 elements:
    //   * segments[0] is ""
    //   * segments[1] is the directory
    //   * segments[2] is the rest of the path, possibly "" if the whole path is "/dirname/"
    if segments.len() == 3 {
        // Access control - users can only access URLs if they are in the group corresponding
        // to the directory
        let directory = segments.get(1).unwrap();
        match claims.custom.groups {
            Some(groups) => {
                if !groups.contains(&directory.to_string()) {
                    return Err(responses::unauthorized(format!("Access to /{} directory denied!", directory)));
                }
            },
            _ => {
                return Err(responses::unauthorized("Missing groups claim"));
            }
        }
    }

    Ok(())
}

fn handle_slo() -> Result<Response, Error> {
    log::debug!("Logging out via SLO");
    Ok(responses::slo_logout(
        cookies::expired("access_token"),
        cookies::expired("id_token"),
    ))
}

fn handle_logout(base_uri: String, settings: &Config, id_token: &&str) -> Result<Response, Error> {
    log::debug!("Logging out");
    let location = format!(
        "{}?id_token_hint={}&post_logout_redirect_uri={}{}",
        settings.openid_configuration.end_session_endpoint,
        id_token,
        base_uri,
        LOGOUT_INTERSTITIAL
    );
    Ok(responses::logout(
        location,
        cookies::expired("access_token"),
        cookies::expired("id_token"),
    ))
}

fn handle_authorization_code(
    req: &mut Request,
    settings: &Config,
    cookie: &HashMap<&str, &str>,
    redirect_uri: &String
) -> Result<Response, Error> {
    // VERIFY THE AUTHORIZATION CODE AND EXCHANGE IT FOR TOKENS.
    log::debug!("In callback; verifying authorization code");

    // Retrieve the code, state and any error data from the query string.
    let qs: CallbackQueryParameters = req.get_query().unwrap();

    // Handle errors from authorization service
    match (qs.error, qs.error_description) {
        (Some(error_value), Some(error_description)) => {
            return Ok(responses::unauthorized(format!("{}: {}", error_value, error_description)));
        },
        (Some(error_value), _) => {
            return Ok(responses::unauthorized(format!("{}", error_value)));
        },
        _ => ()
    }

    // Verify that the state matches what we've stored, and exchange the authorization code for tokens.
    match (cookie.get("state"), cookie.get("code_verifier")) {
        (Some(state), Some(code_verifier)) => {
            // Authenticate the state token returned by the IdP,
            // and verify that the state we stored matches its subject claim.
            match NonceToken::new(settings.config.nonce_secret).get_claimed_state(&qs.state.unwrap()) {
                Some(claimed_state) => {
                    if state != &claimed_state {
                        return Ok(responses::unauthorized("State mismatch."));
                    }
                }
                _ => {
                    return Ok(responses::unauthorized("Could not verify state."));
                }
            };
            // Exchange the authorization code for tokens.
            let mut exchange_res = Request::post(settings.openid_configuration.token_endpoint)
                .with_body_form(&ExchangePayload {
                    client_id: settings.config.client_id,
                    client_secret: settings.config.client_secret,
                    code: &qs.code.unwrap(),
                    code_verifier,
                    grant_type: "authorization_code",
                    redirect_uri: &redirect_uri,
                })
                .unwrap()
                .send(AUTH_SERVER_BACKEND)?;
            // If the exchange is successful, proceed with the original request.
            if exchange_res.get_status().is_success() {
                log::debug!("Verified authorization code; proceeding with original request");

                // Strip the random state from the state cookie value to get the original request.
                let original_req =
                    &state[..(state.len() - settings.config.state_parameter_length)];
                // Deserialize the response from the authorize step.
                let auth = exchange_res.take_body_json::<AuthorizeResponse>().unwrap();
                // Replay the original request, setting the tokens as cookies.
                Ok(responses::temporary_redirect(
                    original_req,
                    cookies::persistent("access_token", &auth.access_token, auth.expires_in),
                    cookies::persistent("id_token", &auth.id_token, auth.expires_in),
                    cookies::expired("code_verifier"),
                    cookies::expired("state"),
                ))
                // Otherwise, surface any errors from the Identity Provider.
            } else {
                Ok(responses::unauthorized(exchange_res.take_body()))
            }
        }
        _ => Ok(responses::unauthorized("State cookies not found.")),
    }
}

fn validate_tokens(
    settings: &Config,
    access_token: &&str,
    id_token: &&str
) -> Result<JWTClaims<GroupsClaim>, Response> {
    log::debug!("Extracted tokens from cookies; validating");
    if settings.config.introspect_access_token {
        // Validate the access token using the OpenID userinfo endpoint;
        // bearer authentication supports opaque, JWT and other token types (PASETO, Hawk),
        // depending on your Identity Provider configuration.
        let mut userinfo_res = match Request::get(settings.openid_configuration.userinfo_endpoint)
            .with_header(AUTHORIZATION, format!("Bearer {}", access_token))
            .send(AUTH_SERVER_BACKEND) {
            Ok(res) => res,
            Err(error) => {
                return Err(responses::unauthorized(Body::from(error.to_string())));
            }
        };

        // Surface any errors and respond early.
        if userinfo_res.get_status().is_client_error() {
            return Err(responses::unauthorized(userinfo_res.take_body()));
        }
        // Validate the JWT access token.
        // Note - Okta Org authorization server sets the audience to itself, rather than the client
        // id of the app, so access token validation fails!
    } else if settings.config.jwt_access_token
        && validate_token_rs256::<NoCustomClaims>(access_token, &settings).is_err()
    {
        return Err(responses::unauthorized("JWT access token invalid."));
    }

    // Validate the ID token.
    match validate_token_rs256::<GroupsClaim>(id_token, &settings) {
        Ok(claims) => Ok(claims),
        Err(error) => Err(responses::unauthorized(format!("ID token invalid: {}", error.to_string())))
    }
}

fn send_to_backend(mut req: Request, allow_browser_caching: bool) -> Result<Response, Error> {
    log::info!("Serving {}", req.get_path());
    match sign_request(&mut req) {
        Ok(_) => (),
        Err(error) => {
            return Ok(responses::unauthorized(format!("Error: {}", error.to_string())));
        },
    }

    match req.send(B2_BACKEND) {
        Ok(mut res) => {
            log::info!("Backend status code: {}", res.get_status());

            if ! allow_browser_caching {
                res.set_header("Cache-Control", "private, no-store");
            }

            Ok(res)
        },
        Err(error) => {
            Ok(responses::unauthorized(format!("Error: {}", error.root_cause().to_string())))
        }
    }
}

fn sign_request(req: &mut Request) -> Result<(), Error> {
    // Get Backblaze B2 credentials
    let config = match SecretStore::open(FASTLY_SECRET_STORE) {
        Ok(store) => store,
        Err(error) => {
            return Err(Error::msg(format!("Error opening secret store: {}", error)));
        }
    };

    let access_key_id = match config.get("B2_APPLICATION_KEY_ID") {
        Some(secret) => match String::from_utf8(secret.plaintext().to_vec()) {
            Ok(id) => id,
            Err(_) => {
                return Err(Error::msg("Can't decode app key id value."))
            }
        },
        _ => return Err(Error::msg("Can't read app key id from config store.")),
    };
    let secret_access_key = match config.get("B2_APPLICATION_KEY") {
        Some(secret) => match String::from_utf8(secret.plaintext().to_vec()) {
            Ok(key) => key,
            Err(_) => {
                return Err(Error::msg("Can't decode app key value."))
            }
        },
        _ => return Err(Error::msg("Can't read app key from config store.")),
    };

    // Extract region from the endpoint
    let backend = match Backend::from_name(B2_BACKEND) {
        Ok(backend) => backend,
        _ => return Err(Error::msg("Can't find backend.")),
    };

    let host = backend.get_host();

    let bucket_region = REGION_REGEX.captures(host.as_str()).unwrap().get(1).unwrap().as_str().to_string();

    let client = awsv4::SignatureClient {
        access_key_id,
        secret_access_key,
        host,
        bucket_region,
        query_string: req.get_query_str().unwrap_or("").to_string()
    };

    let now = Utc::now();
    let sig = client.aws_v4_auth(req.get_method().as_str(), req.get_path(), now);

    req.set_header(AUTHORIZATION, sig);
    req.set_header("x-amz-content-sha256", hash("".to_string()));
    req.set_header("x-amz-date", now.format("%Y%m%dT%H%M%SZ").to_string());

    Ok(())
}
