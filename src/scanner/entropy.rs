pub fn calculate_shannon_entropy(input: &str) -> f64 {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    let len = bytes.len();

    let chunks = bytes.chunks_exact(8);
    let remainder = chunks.remainder();

    for chunk in chunks {
        counts[chunk[0] as usize] += 1;
        counts[chunk[1] as usize] += 1;
        counts[chunk[2] as usize] += 1;
        counts[chunk[3] as usize] += 1;
        counts[chunk[4] as usize] += 1;
        counts[chunk[5] as usize] += 1;
        counts[chunk[6] as usize] += 1;
        counts[chunk[7] as usize] += 1;
    }

    for &b in remainder {
        counts[b as usize] += 1;
    }

    let total_f64 = len as f64;
    let log2_total = total_f64.log2();
    let mut sum = 0.0;

    for &c in &counts {
        if c > 0 {
            let c_f64 = c as f64;
            sum += c_f64 * (log2_total - c_f64.log2());
        }
    }

    sum / total_f64
}

pub fn is_candidate_entropy_token(word: &str, min_len: usize) -> bool {
    if word.len() < min_len || word.len() > 256 {
        return false;
    }

    let trimmed = word.trim_matches(|c: char| {
        c == '"'
            || c == '\''
            || c == '`'
            || c == ';'
            || c == ','
            || c == ':'
            || c == '('
            || c == ')'
            || c == '{'
            || c == '}'
            || c == '['
            || c == ']'
            || c == '<'
            || c == '>'
            || c == '='
    });

    if trimmed.len() < min_len {
        return false;
    }

    let bytes = trimmed.as_bytes();
    let mut has_alpha = false;
    let mut has_digit = false;

    for &b in bytes {
        if (b'a'..=b'z').contains(&b) || (b'A'..=b'Z').contains(&b) {
            has_alpha = true;
        } else if (b'0'..=b'9').contains(&b) {
            has_digit = true;
        } else if b != b'-' && b != b'_' && b != b'.' && b != b'/' && b != b'+' && b != b'=' {
            return false;
        }
    }

    has_alpha && has_digit
}
