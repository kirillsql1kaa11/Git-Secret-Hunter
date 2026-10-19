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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateFamily {
    Hex,
    Base64,
    Alnum,
    Dotted,
}

impl CandidateFamily {
    pub fn label(&self) -> &'static str {
        match self {
            CandidateFamily::Hex => "hex",
            CandidateFamily::Base64 => "base64",
            CandidateFamily::Alnum => "alnum",
            CandidateFamily::Dotted => "dotted",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub value: String,
    pub family: CandidateFamily,
    pub entropy: f64,
    pub total_bits: f64,
}

const MIN_BITS: f64 = 64.0;
const HEX_MIN_ENTROPY: f64 = 3.0;
const ALNUM_MIN_ENTROPY: f64 = 3.5;

pub fn classify_family(value: &str) -> CandidateFamily {
    let mut hex_only = value.len() >= 16;
    let mut has_symbol = false;
    let mut dots = 0;

    for b in value.bytes() {
        match b {
            b'0'..=b'9' => {}
            b'a'..=b'f' | b'A'..=b'F' => {}
            b'+' | b'/' | b'=' | b'-' | b'_' => {
                has_symbol = true;
                hex_only = false;
            }
            b'.' => {
                has_symbol = true;
                hex_only = false;
                dots += 1;
            }
            _ => hex_only = false,
        }
    }

    if hex_only {
        CandidateFamily::Hex
    } else if dots > 0 {
        CandidateFamily::Dotted
    } else if has_symbol {
        CandidateFamily::Base64
    } else {
        CandidateFamily::Alnum
    }
}

pub fn analyze_candidate(
    value: &str,
    entropy_threshold: f64,
    dotted_allowed: bool,
) -> Option<Candidate> {
    let len = value.len();
    if len < 8 || len > 256 {
        return None;
    }

    let mut has_digit = false;
    let mut has_letter = false;
    let mut has_symbol = false;
    let mut hex_only = true;
    let mut dots = 0;
    let mut digits = 0;

    for b in value.bytes() {
        match b {
            b'0'..=b'9' => {
                has_digit = true;
                digits += 1;
            }
            b'a'..=b'f' => has_letter = true,
            b'g'..=b'z' => {
                has_letter = true;
                hex_only = false;
            }
            b'A'..=b'F' => has_letter = true,
            b'G'..=b'Z' => {
                has_letter = true;
                hex_only = false;
            }
            b'+' | b'/' | b'=' | b'-' | b'_' => {
                has_symbol = true;
                hex_only = false;
            }
            b'.' => {
                has_symbol = true;
                hex_only = false;
                dots += 1;
            }
            _ => return None,
        }
    }

    if !has_digit || !has_letter {
        return None;
    }

    let entropy = calculate_shannon_entropy(value);
    let total_bits = entropy * len as f64;

    if total_bits < MIN_BITS {
        return None;
    }

    let family = if hex_only {
        CandidateFamily::Hex
    } else if dots > 0 {
        CandidateFamily::Dotted
    } else if has_symbol {
        CandidateFamily::Base64
    } else {
        CandidateFamily::Alnum
    };

    let accepted = match family {
        CandidateFamily::Hex => entropy >= HEX_MIN_ENTROPY,
        CandidateFamily::Base64 => entropy >= entropy_threshold,
        CandidateFamily::Alnum => {
            entropy >= (entropy_threshold - 0.5).max(ALNUM_MIN_ENTROPY) && digits >= 2
        }
        CandidateFamily::Dotted => dotted_allowed && entropy >= entropy_threshold,
    };

    if !accepted {
        return None;
    }

    Some(Candidate {
        value: value.to_string(),
        family,
        entropy,
        total_bits,
    })
}
