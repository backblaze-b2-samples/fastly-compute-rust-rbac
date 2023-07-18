use std::collections::HashMap;

// Don't use HttpOnly, as we want JS to have access to the cookies
// Need SameSite=None for Okta single logout - need to present cookie in iframe
const COOKIE_ATTRIBUTES: &str = "Path=/; SameSite=None; Secure";
const COOKIE_PREFIX: &str = "b2-fastly-demo-";

pub fn parse(cookie_string: &str) -> HashMap<&str, &str> {
    cookie_string
        .split("; ")
        .filter_map(|kv| {
            kv.find('=').map(|index| {
                let (key, value) = kv.split_at(index);
                let key = key.trim().trim_start_matches(COOKIE_PREFIX);
                let value = value[1..].trim();
                (key, value)
            })
        })
        .collect()
}

pub fn persistent(name: &str, value: &str, max_age: u32) -> String {
    format!(
        "{}{}={}; Max-Age={}; {}",
        COOKIE_PREFIX, name, value, max_age, COOKIE_ATTRIBUTES
    )
}

pub fn expired(name: &str) -> String {
    persistent(name, "expired", 0)
}

pub fn session(name: &str, value: &str) -> String {
    format!("{}{}={}; {}", COOKIE_PREFIX, name, value, COOKIE_ATTRIBUTES)
}
