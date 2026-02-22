use chrono::Utc;

pub fn time_now() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
