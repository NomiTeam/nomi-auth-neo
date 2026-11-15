/// Return the exact public method set without exposing generated documentation routes.
pub fn allowed_methods(path: &str) -> Option<&'static str> {
    match path {
        "/health" | "/api/v1/game/profile" => {
            return Some("GET");
        }
        "/api/v1/logins" => return Some("POST"),
        "/api/v1/sessions/refresh" => return Some("POST, DELETE"),
        "/api/v1/sessions/current" => return Some("DELETE"),
        "/api/v1/me/profile/skin" => return Some("PUT, DELETE"),
        "/internal/v1/logins/verify"
        | "/internal/v1/logins/register"
        | "/internal/v1/profiles/rename" => return Some("POST"),
        "/api/yggdrasil" | "/api/yggdrasil/" => return Some("GET"),
        _ => (),
    }
    if let Some(tail) = path.strip_prefix("/api/v1/logins/") {
        let segments: Vec<_> = tail.split('/').collect();
        return match segments.as_slice() {
            [identifier] if !identifier.is_empty() => Some("GET, DELETE"),
            [identifier, "session"] if !identifier.is_empty() => Some("POST"),
            _ => None,
        };
    }
    if let Some(tail) = path.strip_prefix("/api/v1/game/profiles/")
        && let Some(identifier) = tail.strip_suffix("/name")
    {
        return (!identifier.is_empty() && !identifier.contains('/')).then_some("PATCH");
    }
    if let Some(tail) = path.strip_prefix("/textures/") {
        return (!tail.is_empty() && !tail.contains('/')).then_some("GET");
    }
    let game = path.strip_prefix("/api/yggdrasil/")?;
    match game {
        "authserver/authenticate"
        | "authserver/signout"
        | "authserver/refresh"
        | "authserver/validate"
        | "authserver/invalidate"
        | "sessionserver/session/minecraft/join"
        | "api/profiles/minecraft" => Some("POST"),
        "sessionserver/session/minecraft/hasJoined" => Some("GET"),
        _ if game
            .strip_prefix("sessionserver/session/minecraft/profile/")
            .is_some_and(|identifier| !identifier.is_empty() && !identifier.contains('/')) =>
        {
            Some("GET")
        }
        _ if game
            .strip_prefix("api/user/profile/")
            .and_then(|tail| tail.strip_suffix("/skin"))
            .is_some_and(|identifier| !identifier.is_empty() && !identifier.contains('/')) =>
        {
            Some("PUT")
        }
        _ => None,
    }
}

pub fn uses_json(method: &str, path: &str) -> bool {
    if method == "PATCH" {
        return true;
    }
    if method != "POST" {
        return false;
    }
    if path == "/api/v1/logins" || path.starts_with("/internal/") {
        return true;
    }
    matches!(
        path.strip_prefix("/api/yggdrasil/"),
        Some(
            "authserver/refresh"
                | "authserver/validate"
                | "authserver/invalidate"
                | "sessionserver/session/minecraft/join"
                | "api/profiles/minecraft"
        )
    )
}
