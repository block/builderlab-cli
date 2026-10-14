use blox::proto::WorkstationStatus;

pub(super) fn status_text(status: i32) -> String {
    WorkstationStatus::try_from(status)
        .map(|status| {
            status
                .as_str_name()
                .trim_start_matches("WORKSTATION_STATUS_")
                .to_ascii_lowercase()
        })
        .unwrap_or_else(|_| format!("unknown({status})"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_and_transient_statuses_are_displayable() {
        assert_eq!(status_text(999), "unknown(999)");
        assert_eq!(status_text(9), "pending");
        assert_eq!(status_text(10), "queued");
        assert_eq!(status_text(11), "suspending");
        assert_eq!(status_text(12), "deleting");
    }
}
