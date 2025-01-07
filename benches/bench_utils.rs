use std::time::Duration;

pub fn detect_spx_feature() -> &'static str {
    let active_features = [
        ("sphincs_sha2_128f", cfg!(feature = "sphincs_sha2_128f")),
        ("sphincs_sha2_128s", cfg!(feature = "sphincs_sha2_128s")),
        ("sphincs_sha2_192f", cfg!(feature = "sphincs_sha2_192f")),
        ("sphincs_sha2_192s", cfg!(feature = "sphincs_sha2_192s")),
        ("sphincs_sha2_256f", cfg!(feature = "sphincs_sha2_256f")),
        ("sphincs_sha2_256s", cfg!(feature = "sphincs_sha2_256s")),
        ("sphincs_shake_128f", cfg!(feature = "sphincs_shake_128f")),
        ("sphincs_shake_128s", cfg!(feature = "sphincs_shake_128s")),
        ("sphincs_shake_192f", cfg!(feature = "sphincs_shake_192f")),
        ("sphincs_shake_192s", cfg!(feature = "sphincs_shake_192s")),
        ("sphincs_shake_256f", cfg!(feature = "sphincs_shake_256f")),
        ("sphincs_shake_256s", cfg!(feature = "sphincs_shake_256s")),
    ];

    let active: Vec<_> = active_features
        .iter()
        .filter(|(_, active)| *active)
        .collect();

    match active.len() {
        0 => panic!("No SPHINCS+ feature is active. Exactly one feature must be enabled."),
        1 => active[0].0,
        _ => panic!("Multiple SPHINCS+ features are active. Only one feature must be enabled."),
    }
}

pub fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    let mut parts = vec![];

    if hours > 0 {
        parts.push(format!(
            "{} hour{}",
            hours,
            if hours > 1 { "s" } else { "" }
        ));
    }
    if minutes > 0 {
        parts.push(format!(
            "{} minute{}",
            minutes,
            if minutes > 1 { "s" } else { "" }
        ));
    }
    if seconds > 0 || parts.is_empty() {
        parts.push(format!(
            "{} second{}",
            seconds,
            if seconds > 1 { "s" } else { "" }
        ));
    }

    if parts.len() > 1 {
        let last = parts.pop().unwrap();
        format!("{} and {}", parts.join(", "), last)
    } else {
        parts.join("")
    }
}
