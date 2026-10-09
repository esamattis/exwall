//! Pure rendering of request events as access-log rows.

use super::event::RequestEvent;
use hickory_proto::op::ResponseCode;
use std::{borrow::Cow, fmt::Write};

/// Render every column except the timestamp; equal messages are deduplicated.
pub fn message(event: &RequestEvent) -> String {
    let status = event.http_status.map(|status| status.to_string());
    let rcode = event.dns_rcode.map(rcode_name);
    format!(
        "{} {} {} {} {} {} {} {}",
        event.protocol.name(),
        decision_name(event),
        field(&rule_column(event)),
        field(event.method.as_deref().unwrap_or("-")),
        field(&event.url),
        status.as_deref().unwrap_or("-"),
        rcode.as_deref().unwrap_or("-"),
        event.failure.map(|failure| failure.name()).unwrap_or("-"),
    )
}

/// Produce nine columns and an `xN` suffix when a message occurred `count > 1` times.
pub fn line(event: &RequestEvent, count: usize) -> String {
    let suffix = if count > 1 {
        format!(" x{count}")
    } else {
        String::new()
    };
    format!("{} {}{suffix}\n", event.timestamp, message(event))
}

/// Render DNS response codes as stable, uppercase access-log tokens.
pub fn rcode_name(code: ResponseCode) -> Cow<'static, str> {
    match code {
        ResponseCode::NoError => "NOERROR".into(),
        ResponseCode::FormErr => "FORMERR".into(),
        ResponseCode::ServFail => "SERVFAIL".into(),
        ResponseCode::NXDomain => "NXDOMAIN".into(),
        ResponseCode::NotImp => "NOTIMP".into(),
        ResponseCode::Refused => "REFUSED".into(),
        other => u16::from(other).to_string().into(),
    }
}

/// Render the policy decision column.
fn decision_name(event: &RequestEvent) -> &'static str {
    match event.decision {
        crate::policy::Decision::Allow => "ALLOW",
        crate::policy::Decision::Deny => "DENY",
        crate::policy::Decision::Unevaluated => "-",
    }
}

/// Join match labels in question order, using `-` for unmatched entries.
fn rule_column(event: &RequestEvent) -> String {
    if event.matches.is_empty() {
        return "-".into();
    }
    let labels: Vec<String> = event
        .matches
        .iter()
        .map(|source| match source {
            Some(source) => source.to_string(),
            None => "-".into(),
        })
        .collect();
    labels.join(",")
}

/// Escape whitespace, controls, and percent signs to keep request data on one line.
pub fn field(value: &str) -> String {
    if value.is_empty() {
        return "-".into();
    }
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_whitespace() || character.is_control() || character == '%' {
            let mut bytes = [0; 4];
            for byte in character.encode_utf8(&mut bytes).bytes() {
                write!(output, "%{byte:02X}").expect("writing to a String cannot fail");
            }
        } else {
            output.push(character);
        }
    }
    output
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        policy::{Decision, MatchSource, RuleId},
        telemetry::event::{Failure, Protocol},
    };

    /// Build an allowed HTTP event with deterministic contents for format assertions.
    pub(crate) fn event(index: usize) -> RequestEvent {
        let mut event = RequestEvent::http(Protocol::Http, "GET", format!("http://test/{index}"));
        event.timestamp = "2026-10-07T12:34:56Z".parse().unwrap();
        event.matched(MatchSource::Rule(RuleId::new("test", 1)));
        event.decide(Decision::Allow);
        event.respond_http(200);
        event
    }

    /// Verify that attacker-controlled fields cannot inject rows or extra columns.
    #[test]
    fn formats_separate_columns_without_log_injection() {
        let mut event = event(0);
        event.matches = vec![Some(MatchSource::Rule(RuleId::new("file name\nforged", 1)))];
        event.url = "http://test/?q=%20\r\n\t\u{2003}".into();
        assert_eq!(
            line(&event, 1),
            "2026-10-07T12:34:56Z http ALLOW file%20name%0Aforged:allow#1 GET http://test/?q=%2520%0D%0A%09%E2%80%83 200 - -\n"
        );
        assert_eq!(line(&event, 1).split_whitespace().count(), 9);
    }

    /// Preserve the same client status while distinguishing upstream responses from proxy failures.
    #[test]
    fn separates_http_status_from_processing_error() {
        let mut upstream = event(0);
        upstream.respond_http(502);
        assert!(
            line(&upstream, 1).contains(" http ALLOW test:allow#1 GET http://test/0 502 - -\n")
        );
        upstream.fail(Failure::Upstream);
        assert!(
            line(&upstream, 1)
                .contains(" http ALLOW test:allow#1 GET http://test/0 502 - UPSTREAM_FAILURE\n")
        );
        upstream.fail(Failure::UpstreamTimeout);
        assert!(line(&upstream, 1).ends_with(" 502 - UPSTREAM_TIMEOUT\n"));
    }

    /// DNS rows use `-` for HTTP columns and list per-question labels.
    #[test]
    fn formats_dns_rows() {
        let mut event = RequestEvent::dns();
        event.timestamp = "2026-10-07T12:34:56Z".parse().unwrap();
        assert!(line(&event, 1).ends_with(" dns - - - - - - CANCELLED\n"));
        event.url = "dns://a.test/A,dns://b.test/AAAA".into();
        event.matches = vec![Some(MatchSource::DnsBypass), None];
        event.decide(Decision::Deny);
        event.respond_dns(ResponseCode::Refused);
        assert_eq!(
            line(&event, 3),
            "2026-10-07T12:34:56Z dns DENY @dns-bypass,- - dns://a.test/A,dns://b.test/AAAA - REFUSED - x3\n"
        );
        assert_eq!(rcode_name(ResponseCode::NXDomain), "NXDOMAIN");
        assert_eq!(rcode_name(ResponseCode::BADVERS), "16");
    }
}
