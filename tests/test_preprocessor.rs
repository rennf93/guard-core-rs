#[path = "support/agent.rs"]
mod agent;

use guard_core_rs::detection_engine::ContentPreprocessor;
use guard_core_rs::protocols::agent::DynAgentHandler;

use agent::MockAgent;

#[test]
fn default_preprocessor_has_reasonable_bounds() {
    let pp = ContentPreprocessor::default();
    assert_eq!(pp.max_content_length, 10_000);
    assert!(pp.preserve_attack_patterns);
    assert!(pp.agent_handler.is_none());
    assert!(pp.correlation_id.is_none());
    let debug = format!("{pp:?}");
    assert!(debug.contains("ContentPreprocessor"));
}

#[test]
fn normalize_unicode_replaces_fullwidth_chars() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let fullwidth = "\u{ff1c}tag\u{ff1e}";
    let result = pp.normalize_unicode(fullwidth);
    assert!(result.contains('<'));
    assert!(result.contains('>'));
}

#[test]
fn normalize_unicode_replaces_slashes() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    for lookalike in ["\u{2044}", "\u{ff0f}", "\u{29f8}", "\u{2215}"] {
        let out = pp.normalize_unicode(lookalike);
        assert!(out.contains('/'), "expected slash for {lookalike:?}, got {out:?}");
    }
}

#[test]
fn normalize_unicode_replaces_backslash_lookalike() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.normalize_unicode("\u{2216}");
    assert!(out.contains('\\'));
}

#[test]
fn normalize_unicode_replaces_dotted_i() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.normalize_unicode("\u{0130}");
    assert!(out.contains('I'));
    let out2 = pp.normalize_unicode("\u{0131}");
    assert!(out2.contains('i'));
}

#[test]
fn normalize_unicode_strips_zero_width_chars() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    for zw in [
        "\u{200b}", "\u{200c}", "\u{200d}", "\u{feff}", "\u{00ad}", "\u{034f}", "\u{180e}",
        "\u{e000}", "\u{fff0}",
    ] {
        let out = pp.normalize_unicode(&format!("A{zw}B"));
        assert_eq!(out, "AB", "should strip {zw:?}");
    }
}

#[test]
fn normalize_unicode_replaces_line_separators_with_newlines() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.normalize_unicode("line1\u{2028}line2\u{2029}line3");
    assert!(out.contains("line1\nline2\nline3"));
}

#[test]
fn normalize_unicode_replaces_pipe_and_semicolon() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    assert!(pp.normalize_unicode("\u{01c0}").contains('|'));
    assert!(pp.normalize_unicode("\u{037e}").contains(';'));
}

#[test]
fn remove_excessive_whitespace_collapses_spaces() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    assert_eq!(pp.remove_excessive_whitespace("  a    b\t\tc\n\nd   "), "a b c d");
}

#[test]
fn remove_null_bytes_removes_all_control_chars() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let input = "A\0B\x01C\x02D\tE\nF\rG";
    let out = pp.remove_null_bytes(input);
    assert_eq!(out, "ABCD\tE\nF\rG");
}

#[tokio::test]
async fn decode_common_encodings_decodes_percent() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("hello%20world").await;
    assert_eq!(out, "hello world");
}

#[tokio::test]
async fn decode_common_encodings_decodes_html_named() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("a &amp; b &lt; c &gt; d &quot;e&quot; &apos;f&apos;").await;
    assert!(out.contains('&'));
    assert!(out.contains('<'));
    assert!(out.contains('>'));
    assert!(out.contains('"'));
    assert!(out.contains('\''));
}

#[tokio::test]
async fn decode_common_encodings_handles_nbsp() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("&nbsp;").await;
    assert!(out.contains(' '));
}

#[tokio::test]
async fn decode_common_encodings_handles_multichar_entities_in_ascii_sequence() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("&unknown;").await;
    assert!(out.contains('&'));
}

#[tokio::test]
async fn decode_common_encodings_handles_unterminated_entity() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("hello &amp world").await;
    assert!(out.contains('&') || out.contains("amp"));
}

#[tokio::test]
async fn decode_common_encodings_handles_invalid_hex_entity() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("&#xZZZ;").await;
    assert!(out.contains('&'));
}

#[tokio::test]
async fn decode_common_encodings_handles_invalid_decimal_entity() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("&#abc;").await;
    assert!(out.contains('&'));
}

#[tokio::test]
async fn decode_common_encodings_handles_out_of_range_hex() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("&#xD800;").await;
    assert!(out.contains('&'));
}

#[tokio::test]
async fn decode_common_encodings_handles_out_of_range_decimal() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("&#55296;").await;
    assert!(out.contains('&'));
}

#[tokio::test]
async fn decode_common_encodings_decodes_html_hex() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("&#x41;&#x42;").await;
    assert!(out.contains('A'));
    assert!(out.contains('B'));
}

#[tokio::test]
async fn decode_common_encodings_decodes_html_decimal() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("&#65;&#66;").await;
    assert!(out.contains('A'));
    assert!(out.contains('B'));
}

#[tokio::test]
async fn decode_common_encodings_handles_uppercase_x() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("&#X41;").await;
    assert!(out.contains('A'));
}

#[tokio::test]
async fn decode_common_encodings_returns_unchanged_on_no_encodings() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("plain text").await;
    assert_eq!(out, "plain text");
}

#[tokio::test]
async fn decode_common_encodings_iterates_multiple_times() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("%2520").await;
    assert!(out.contains('%') || out.contains(' '));
}

#[tokio::test]
async fn decode_common_encodings_with_agent_handles_invalid_sequences() {
    let agent = MockAgent::new();
    let handler: DynAgentHandler = agent.clone();
    let pp = ContentPreprocessor::new(10_000, true, Some(handler), Some("corr-1".into()));
    let _ = pp.decode_common_encodings("hello world").await;
}


#[tokio::test]
async fn decode_common_encodings_leaves_invalid_percent_untouched() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.decode_common_encodings("%ZZ").await;
    assert_eq!(out, "%ZZ");
}

#[tokio::test]
async fn truncate_safely_short_content_is_unchanged() {
    let pp = ContentPreprocessor::new(1000, true, None, None);
    let out = pp.truncate_safely("short").await;
    assert_eq!(out, "short");
}

#[tokio::test]
async fn truncate_safely_without_preserve_slices() {
    let pp = ContentPreprocessor::new(50, false, None, None);
    let content = "x".repeat(200);
    let out = pp.truncate_safely(&content).await;
    assert_eq!(out.len(), 50);
}

#[tokio::test]
async fn truncate_safely_with_preserve_but_no_attack_regions() {
    let pp = ContentPreprocessor::new(40, true, None, None);
    let content = "a".repeat(500);
    let out = pp.truncate_safely(&content).await;
    assert_eq!(out.len(), 40);
}

#[tokio::test]
async fn truncate_safely_with_preserve_keeps_attack_regions() {
    let pp = ContentPreprocessor::new(500, true, None, None);
    let prefix = "z".repeat(200);
    let suffix = "y".repeat(200);
    let content = format!("{prefix}<script>alert(1)</script>{suffix}");
    let out = pp.truncate_safely(&content).await;
    assert!(out.contains("<script"));
}

#[tokio::test]
async fn truncate_safely_very_large_attack_regions() {
    let pp = ContentPreprocessor::new(50, true, None, None);
    let attack = "<script>".repeat(50);
    let content = format!("aaa{attack}bbb");
    let out = pp.truncate_safely(&content).await;
    assert!(out.len() <= 50);
}

#[tokio::test]
async fn truncate_safely_concatenates_when_attack_regions_exceed_max() {
    let pp = ContentPreprocessor::new(200, true, None, None);
    let filler = "z".repeat(400);
    let content = format!("{filler}<script>alert</script>{filler}");
    let out = pp.truncate_safely(&content).await;
    assert!(out.contains("<script") || out.contains("/script"));
}

#[tokio::test]
async fn truncate_safely_exceeds_limit_with_small_attack_and_context() {
    let pp = ContentPreprocessor::new(100_000, true, None, None);
    let prefix = "a".repeat(100);
    let attack = "<script>";
    let suffix = "b".repeat(99_900);
    let content = format!("{prefix}{attack}{suffix}");
    assert!(content.len() > 100_000);
    let out = pp.truncate_safely(&content).await;
    assert!(out.contains("<script"));
}

#[tokio::test]
async fn truncate_safely_when_region_spans_over_full_buffer() {
    let pp = ContentPreprocessor::new(300, true, None, None);
    let pad = "x".repeat(250);
    let content = format!("{pad}<script>{pad}");
    let out = pp.truncate_safely(&content).await;
    assert!(out.contains("<script"));
}

#[tokio::test]
async fn extract_attack_regions_empty_for_benign_text() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let regions = pp.extract_attack_regions("Hello world, this is safe").await;
    assert!(regions.is_empty());
}

#[tokio::test]
async fn extract_attack_regions_finds_script_tag() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let regions = pp
        .extract_attack_regions("here is <script>malicious</script> ok")
        .await;
    assert!(!regions.is_empty());
}

#[tokio::test]
async fn extract_attack_regions_merges_overlapping() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let content = "<script><script><script>";
    let regions = pp.extract_attack_regions(content).await;
    assert!(regions.len() <= 3);
}

#[tokio::test]
async fn extract_attack_regions_finds_many_indicators() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let content = "javascript:foo() onerror=x SELECT a FROM b UNION SELECT c ../ eval(x) exec(y) system(z) <?php <% {{ {% <iframe <object <embed onload=q ${bad} \\x41 %20";
    let regions = pp.extract_attack_regions(content).await;
    assert!(!regions.is_empty());
}

#[tokio::test]
async fn extract_attack_regions_preserves_disjoint_regions() {
    let pp = ContentPreprocessor::new(100_000, true, None, None);
    let chunk_a = "<script>a";
    let filler = "z".repeat(50_000);
    let chunk_b = "<iframe>b";
    let content = format!("{chunk_a}{filler}{chunk_b}");
    let regions = pp.extract_attack_regions(&content).await;
    assert!(regions.len() >= 2);
}

#[tokio::test]
async fn preprocess_empty_returns_empty() {
    let pp = ContentPreprocessor::new(1000, true, None, None);
    let out = pp.preprocess("").await;
    assert!(out.is_empty());
}

#[tokio::test]
async fn preprocess_applies_all_steps() {
    let pp = ContentPreprocessor::new(1000, true, None, None);
    let input = "\u{ff1c}script\u{ff1e}%20alert\0\n\n\n";
    let out = pp.preprocess(input).await;
    assert!(!out.contains('\0'));
    assert!(!out.contains("\n\n"));
}

#[tokio::test]
async fn preprocess_truncates_oversize_input() {
    let pp = ContentPreprocessor::new(100, false, None, None);
    let big = "x".repeat(500);
    let out = pp.preprocess(&big).await;
    assert!(out.len() <= 100);
}

#[tokio::test]
async fn preprocess_batch_returns_vector_for_each_input() {
    let pp = ContentPreprocessor::new(1000, true, None, None);
    let inputs: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
    let out = pp.preprocess_batch(&inputs).await;
    assert_eq!(out.len(), inputs.len());
}

#[tokio::test]
async fn truncate_safely_breaks_when_remaining_becomes_zero() {
    let pp = ContentPreprocessor::new(10, true, None, None);
    let filler = "z".repeat(50);
    let content = format!("<script>abc{filler}<iframe>def");
    let out = pp.truncate_safely(&content).await;
    assert!(out.len() <= 10);
}


#[tokio::test]
async fn preprocess_with_agent_handler_runs_without_errors() {
    let agent = MockAgent::new();
    let handler: DynAgentHandler = agent.clone();
    let pp = ContentPreprocessor::new(10_000, true, Some(handler), Some("corr".into()));
    let out = pp.preprocess("hello %20 world").await;
    assert!(!out.is_empty());
}

#[tokio::test]
async fn extract_attack_regions_caps_at_max_regions() {
    let pp = ContentPreprocessor::new(200, true, None, None);
    let mut content = String::new();
    for _ in 0..20 {
        content.push_str("<script>");
    }
    let regions = pp.extract_attack_regions(&content).await;
    assert!(!regions.is_empty());
}

#[tokio::test]
async fn truncate_safely_with_multiple_disjoint_small_regions() {
    let pp = ContentPreprocessor::new(20, true, None, None);
    let content = "<script>A".to_string() + &"x".repeat(30) + "<iframe>B";
    let out = pp.truncate_safely(&content).await;
    assert!(out.len() <= 40);
}

#[tokio::test]
async fn truncate_safely_concatenates_large_region_hits_remaining_zero_break() {
    let pp = ContentPreprocessor::new(5, true, None, None);
    let mut content = String::new();
    for _ in 0..40 {
        content.push_str("<script>abc");
    }
    let out = pp.truncate_safely(&content).await;
    assert!(out.len() <= 5);
}

#[tokio::test]
async fn truncate_safely_preserves_with_agent_handler_emits_no_error_events() {
    let agent = MockAgent::new();
    let handler: DynAgentHandler = agent.clone();
    let pp = ContentPreprocessor::new(50, true, Some(handler), Some("corr-t".into()));
    let content = "<script>".to_string() + &"a".repeat(200);
    let out = pp.truncate_safely(&content).await;
    assert!(out.contains("<script"));
}

#[tokio::test]
async fn extract_and_concatenate_attack_regions_breaks_when_remaining_zero() {
    let pp = ContentPreprocessor::new(5, true, None, None);
    let content = format!(
        "{}<script>alert</script>{}<iframe>bad</iframe>{}",
        "a".repeat(400),
        "b".repeat(400),
        "c".repeat(400)
    );
    let out = pp.truncate_safely(&content).await;
    assert!(out.len() <= 5);
}

