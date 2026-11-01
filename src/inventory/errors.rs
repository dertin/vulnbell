pub(super) fn safe_inventory_error(error: &anyhow::Error) -> String {
    if let Some(error) = error.downcast_ref::<serde_json::Error>() {
        return format!(
            "JSON inventory parse failed at line {}, column {}; source content omitted",
            error.line(),
            error.column()
        );
    }
    if let Some(error) = error.downcast_ref::<toml::de::Error>() {
        return format!(
            "TOML inventory parse failed at byte span {:?}; source content omitted",
            error.span()
        );
    }
    if let Some(error) = error.downcast_ref::<serde_saphyr::Error>() {
        return match error.location() {
            Some(location) => format!(
                "YAML inventory parse failed at line {}, column {}; source content omitted",
                location.line(),
                location.column()
            ),
            None => "YAML inventory parse failed; source content omitted".into(),
        };
    }
    error.to_string()
}
