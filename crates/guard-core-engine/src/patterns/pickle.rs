//! Pickle opcode-stream validation ported from
//! `guard_core/handlers/_suspatterns_pickle.py` (spec 4.0.2).
//!
//! The reference walks a bounded 4096-byte window through the CPython pickle
//! opcode dispatch (with class resolution, extension registry and persistent
//! loading blocked). The walk answers exactly two questions: does the prefix
//! before a candidate look like a valid opcode stream, and does the suffix
//! after it reach a REDUCE/BUILD opcode without an error.

const PICKLE_OPCODE_WORK_BUDGET_BYTES: usize = 4096;

const REDUCE: u8 = 0x52; // 'R'
const BUILD: u8 = 0x62; // 'b'
const FRAME_OPCODE: u8 = 0x95;

#[derive(Debug)]
enum WalkError {
    ShortRead,
    Blocked,
}

struct WalkState<'a> {
    window: &'a [u8],
    pos: usize,
    stack: Vec<u8>,
    marks: Vec<usize>,
    memo: std::collections::HashMap<u32, u8>,
}

fn pickle_read(state: &mut WalkState, size: usize) -> Result<Vec<u8>, WalkError> {
    if state.pos + size > state.window.len() {
        return Err(WalkError::ShortRead);
    }
    let bytes = state.window[state.pos..state.pos + size].to_vec();
    state.pos += size;
    Ok(bytes)
}

fn pickle_readline(state: &mut WalkState) -> Result<Vec<u8>, WalkError> {
    let mut line = Vec::new();
    loop {
        if state.pos >= state.window.len() {
            return Err(WalkError::ShortRead);
        }
        let byte = state.window[state.pos];
        state.pos += 1;
        line.push(byte);
        if byte == 0x0a {
            break;
        }
    }
    Ok(line)
}

fn le_int(bytes: &[u8]) -> usize {
    let mut value = 0usize;
    for b in bytes.iter().rev() {
        value = value * 0x100 + usize::from(*b);
    }
    value
}

fn push_mark(state: &mut WalkState) {
    state.marks.push(state.stack.len());
}

fn pop_mark(state: &mut WalkState) -> Result<(), WalkError> {
    let Some(mark) = state.marks.pop() else {
        return Err(WalkError::Blocked);
    };
    // discard the marked segment like the reference's stack juggling
    while state.stack.len() > mark {
        state.stack.pop();
    }
    Ok(())
}

fn is_digits(text: &[u8]) -> bool {
    !text.is_empty() && text.iter().all(|b| b.is_ascii_digit())
}

fn dispatch_opcode(state: &mut WalkState, key: u8) -> Result<(), WalkError> {
    match key {
        0x28 => {
            // '(' MARK
            push_mark(state);
            Ok(())
        }
        0x30 => {
            // '0' POP
            state.stack.pop().map_or(Err(WalkError::Blocked), |_| Ok(()))
        }
        0x31 => pop_mark(state), // '1' POP_MARK
        0x32 => {
            // '2' DUP
            let Some(last) = state.stack.last().copied() else {
                return Err(WalkError::Blocked);
            };
            state.stack.push(last);
            Ok(())
        }
        0x5d | 0x7d | 0x29 => {
            // ']' EMPTY_LIST, '}' EMPTY_DICT, ')' EMPTY_TUPLE
            state.stack.push(1);
            Ok(())
        }
        0x6c | 0x74 | 0x64 => {
            // 'l' LIST, 't' TUPLE, 'd' DICT
            pop_mark(state)?;
            state.stack.push(1);
            Ok(())
        }
        0x61 => {
            // 'a' APPEND
            state.stack.pop().map_or(Err(WalkError::Blocked), |_| Ok(()))
        }
        0x65 => pop_mark(state), // 'e' APPENDS
        0x73 => {
            // 's' SETITEM
            state.stack.pop().map_or(Err(WalkError::Blocked), |_| Ok(()))?;
            state.stack.pop().map_or(Err(WalkError::Blocked), |_| Ok(()))
        }
        0x75 => pop_mark(state), // 'u' SETITEMS
        0x4e | 0x89 | 0x88 => {
            // 'N' NONE, NEWFALSE, NEWTRUE
            state.stack.push(1);
            Ok(())
        }
        0x49 => {
            // 'I' INT
            let data = pickle_readline(state)?;
            let text = &data[..data.len().saturating_sub(1)];
            if text == b"01" || text == b"00" {
                return Ok(());
            }
            if text.first() == Some(&b'-') && is_digits(&text[1..]) {
                return Ok(());
            }
            if is_digits(text) {
                return Ok(());
            }
            Err(WalkError::Blocked)
        }
        0x4c => {
            // 'L' LONG
            let data = pickle_readline(state)?;
            let mut text = &data[..data.len().saturating_sub(1)];
            if text.last() == Some(&b'L') {
                text = &text[..text.len() - 1];
            }
            if text.first() == Some(&b'-') && is_digits(&text[1..]) {
                return Ok(());
            }
            if is_digits(text) {
                return Ok(());
            }
            Err(WalkError::Blocked)
        }
        0x46 => {
            // 'F' FLOAT
            let data = pickle_readline(state)?;
            let text = std::str::from_utf8(&data[..data.len().saturating_sub(1)])
                .map_err(|_| WalkError::Blocked)?;
            if text.parse::<f64>().is_ok() {
                Ok(())
            } else {
                Err(WalkError::Blocked)
            }
        }
        0x4a => {
            pickle_read(state, 4)?;
            Ok(())
        }
        0x4b => {
            pickle_read(state, 1)?;
            Ok(())
        }
        0x4d => {
            pickle_read(state, 2)?;
            Ok(())
        }
        0x47 => {
            pickle_read(state, 8)?;
            Ok(())
        }
        0x53 => {
            // 'S' STRING
            let data = pickle_readline(state)?;
            let body = &data[..data.len().saturating_sub(1)];
            if body.len() < 2
                || body[0] != body[body.len() - 1]
                || (body[0] != 0x22 && body[0] != 0x27)
            {
                return Err(WalkError::Blocked);
            }
            Ok(())
        }
        0x56 => {
            pickle_readline(state)?;
            Ok(())
        }
        0x58 => {
            let length = le_int(&pickle_read(state, 4)?);
            pickle_read(state, length)?;
            Ok(())
        }
        0x8c => {
            let length = pickle_read(state, 1)?[0] as usize;
            pickle_read(state, length)?;
            Ok(())
        }
        0x54 => {
            let length = le_int(&pickle_read(state, 4)?);
            pickle_read(state, length)?;
            Ok(())
        }
        0x55 => {
            let length = pickle_read(state, 1)?[0] as usize;
            pickle_read(state, length)?;
            Ok(())
        }
        0x42 => {
            let length = le_int(&pickle_read(state, 4)?);
            pickle_read(state, length)?;
            Ok(())
        }
        0x8e => {
            let length = le_int(&pickle_read(state, 8)?);
            pickle_read(state, length)?;
            Ok(())
        }
        0x43 => {
            let length = pickle_read(state, 1)?[0] as usize;
            pickle_read(state, length)?;
            Ok(())
        }
        0x96 => {
            let length = le_int(&pickle_read(state, 8)?);
            pickle_read(state, length)?;
            Ok(())
        }
        0x8a => {
            let length = pickle_read(state, 1)?[0] as usize;
            pickle_read(state, length)?;
            Ok(())
        }
        0x8b => {
            let length = le_int(&pickle_read(state, 4)?);
            pickle_read(state, length)?;
            Ok(())
        }
        0x80 => {
            pickle_read(state, 1)?;
            Ok(())
        }
        0x94 => {
            // MEMOIZE
            if state.stack.is_empty() {
                return Err(WalkError::Blocked);
            }
            let synthetic = u32::try_from(state.memo.len()).unwrap_or(u32::MAX);
            state.memo.insert(synthetic, 1);
            Ok(())
        }
        0x71 => {
            // 'q' BINPUT
            let index = pickle_read(state, 1)?[0];
            if state.stack.is_empty() {
                return Err(WalkError::Blocked);
            }
            memo_set(state, u32::from(index));
            Ok(())
        }
        0x72 => {
            // 'r' LONG_BINPUT
            let index = le_int(&pickle_read(state, 4)?);
            if state.stack.is_empty() {
                return Err(WalkError::Blocked);
            }
            memo_set(state, u32::try_from(index).unwrap_or(u32::MAX));
            Ok(())
        }
        0x68 => {
            // 'h' BINGET
            let index = pickle_read(state, 1)?[0];
            if !memo_has(state, u32::from(index)) {
                return Err(WalkError::Blocked);
            }
            state.stack.push(1);
            Ok(())
        }
        0x6a => {
            // 'j' LONG_BINGET
            let index = le_int(&pickle_read(state, 4)?);
            if !memo_has(state, u32::try_from(index).unwrap_or(u32::MAX)) {
                return Err(WalkError::Blocked);
            }
            state.stack.push(1);
            Ok(())
        }
        0x67 => {
            // 'g' GET
            let data = pickle_readline(state)?;
            let text = std::str::from_utf8(&data[..data.len().saturating_sub(1)])
                .map_err(|_| WalkError::Blocked)?;
            let index: usize = text.parse().map_err(|_| WalkError::Blocked)?;
            if !memo_has(state, u32::try_from(index).unwrap_or(u32::MAX)) {
                return Err(WalkError::Blocked);
            }
            state.stack.push(1);
            Ok(())
        }
        // 'c' GLOBAL, 'i' INST, 'o' OBJ, NEWOBJ, NEWOBJ_EX, STACK_GLOBAL,
        // PERSID, BINPERSID, EXT1/2/4: class resolution blocked
        0x63 | 0x69 | 0x6f | 0x81 | 0x82 | 0x93 | 0x50 | 0x51 | 0x84 | 0x85 | 0x86 => {
            Err(WalkError::Blocked)
        }
        _ => Err(WalkError::Blocked),
    }
}

fn memo_set(state: &mut WalkState, index: u32) {
    state.memo.insert(index, 1);
}

fn memo_has(state: &WalkState, index: u32) -> bool {
    state.memo.get(&index).is_some_and(|v| *v == 1)
}

/// Returns `Some(true)` (verdict reached: stream valid / REDUCE or BUILD hit),
/// `Some(false)` (unknown opcode, blocked resolution, malformed payload, or a
/// complete window that exhausted without a verdict), or `None` (window
/// exhausted before a verdict could form; treated like `true` by the
/// reference's `is not False` checks).
fn walk_opcodes(
    state: &mut WalkState,
    stop_at_reduce_or_build: bool,
    is_complete: bool,
) -> Option<bool> {
    while state.pos < state.window.len() {
        let key = match pickle_read(state, 1) {
            Ok(bytes) => bytes[0],
            Err(WalkError::ShortRead) => return (!is_complete).then_some(true),
            Err(WalkError::Blocked) => return Some(false),
        };
        if stop_at_reduce_or_build && (key == REDUCE || key == BUILD) {
            return Some(true);
        }
        if key == FRAME_OPCODE {
            match pickle_read(state, 8) {
                Ok(_) => continue,
                Err(WalkError::ShortRead) => return (!is_complete).then_some(true),
                Err(WalkError::Blocked) => return Some(false),
            }
        }
        match dispatch_opcode(state, key) {
            Ok(()) => {}
            Err(WalkError::ShortRead) => return (!is_complete).then_some(true),
            Err(WalkError::Blocked) => return Some(false),
        }
    }
    if is_complete {
        Some(if stop_at_reduce_or_build { false } else { true })
    } else {
        Some(true)
    }
}

fn fresh_state<'a>(window: &'a [u8], seed_stack: bool) -> WalkState<'a> {
    WalkState {
        window,
        pos: 0,
        stack: if seed_stack { vec![1] } else { Vec::new() },
        marks: Vec::new(),
        memo: std::collections::HashMap::new(),
    }
}

/// Python `_pickle_prefix_window_from_chars`; `None` when not byte-safe.
fn window_from_chars(chars: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(chars.len());
    for c in chars.chars() {
        let code = u32::from(c);
        if code <= 0xff {
            bytes.push(code as u8);
        } else if (0xdc80..=0xdcff).contains(&code) {
            bytes.push((code - 0xdc80 + 0x80) as u8);
        } else {
            return None;
        }
    }
    Some(bytes)
}

#[must_use]
pub fn pickle_prefix_is_opcode_stream(prefix: &str) -> bool {
    if prefix.is_empty() || prefix.ends_with('\n') {
        return true;
    }
    let is_complete = prefix.len() <= PICKLE_OPCODE_WORK_BUDGET_BYTES;
    let Some(window) = window_from_chars(if is_complete {
        prefix
    } else {
        &prefix[..PICKLE_OPCODE_WORK_BUDGET_BYTES]
    }) else {
        return false;
    };
    // a None verdict (incomplete window) is tolerated by the reference
    walk_opcodes(&mut fresh_state(&window, false), false, is_complete) != Some(false)
}

#[must_use]
pub fn pickle_suffix_reaches_reduce_or_build(suffix: &str) -> bool {
    let is_complete = suffix.len() <= PICKLE_OPCODE_WORK_BUDGET_BYTES;
    let Some(window) = window_from_chars(if is_complete {
        suffix
    } else {
        &suffix[..PICKLE_OPCODE_WORK_BUDGET_BYTES]
    }) else {
        return false;
    };
    walk_opcodes(&mut fresh_state(&window, true), true, is_complete) != Some(false)
}

/// `_pickle_global_candidate_is_injection`: the prefix before the candidate
/// must walk as a valid opcode stream and the suffix after the class-name
/// group must reach REDUCE or BUILD.
#[must_use]
pub fn pickle_global_candidate_is_injection(
    haystack: &str,
    candidate: super::pyregex::Candidate,
    group_one_end: usize,
) -> bool {
    if !pickle_prefix_is_opcode_stream(&haystack[..candidate.start]) {
        return false;
    }
    pickle_suffix_reaches_reduce_or_build(&haystack[group_one_end..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_prefix_is_stream_like() {
        // empty or newline-terminated prefixes are trivially accepted
        assert!(pickle_prefix_is_opcode_stream(""));
        assert!(pickle_prefix_is_opcode_stream("hello\n"));
    }

    #[test]
    fn proto_stream_prefix_walks() {
        // "\x80\x04\x95" + 8 size bytes + "\x8c\x04main"
        let mut bytes = vec![0x80u8, 0x04, 0x95];
        bytes.extend_from_slice(&[0x00; 8]);
        bytes.extend_from_slice(&[0x8c, 0x04, b'm', b'a', b'i', b'n']);
        let text: String = bytes.iter().map(|b| char::from(*b)).collect();
        assert!(pickle_prefix_is_opcode_stream(&text));
    }

    #[test]
    fn reduce_opcode_stops_suffix_walk() {
        let mut bytes = vec![0x80u8, 0x04, 0x95];
        bytes.extend_from_slice(&[0x00; 8]);
        bytes.push(b'R');
        let text: String = bytes.iter().map(|b| char::from(*b)).collect();
        assert!(pickle_suffix_reaches_reduce_or_build(&text));
    }

    #[test]
    fn unknown_opcode_fails() {
        assert!(!pickle_suffix_reaches_reduce_or_build("\u{1}nonsense"));
    }
}
