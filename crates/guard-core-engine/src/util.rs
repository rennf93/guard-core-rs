/// Walk down to a UTF-8 char boundary at or before `i`.
pub fn floor_boundary(s: &str, i: usize) -> usize {
    let mut i = i.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Walk up to a UTF-8 char boundary at or after `i`.
pub fn ceil_boundary(s: &str, i: usize) -> usize {
    let mut i = i.min(s.len());
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_boundary_handles_multibyte() {
        let s = "a\u{1F600}b"; // a + 4-byte emoji + b
        assert_eq!(floor_boundary(s, 0), 0);
        assert_eq!(floor_boundary(s, 1), 1);
        // 2..5 lands inside emoji codepoint
        assert_eq!(floor_boundary(s, 2), 1);
        assert_eq!(floor_boundary(s, 3), 1);
        assert_eq!(floor_boundary(s, 4), 1);
        assert_eq!(floor_boundary(s, 5), 5);
        assert_eq!(floor_boundary(s, 999), 6);
    }

    #[test]
    fn ceil_boundary_handles_multibyte() {
        let s = "a\u{1F600}b";
        assert_eq!(ceil_boundary(s, 0), 0);
        assert_eq!(ceil_boundary(s, 1), 1);
        assert_eq!(ceil_boundary(s, 2), 5);
        assert_eq!(ceil_boundary(s, 3), 5);
        assert_eq!(ceil_boundary(s, 4), 5);
        assert_eq!(ceil_boundary(s, 5), 5);
        assert_eq!(ceil_boundary(s, 999), 6);
    }
}
