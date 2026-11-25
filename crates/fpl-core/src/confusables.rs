//! Confusable-character folding for homoglyph detection (the "SayIor" and
//! "breezyhr.us" mechanics from the concept spec).
//!
//! Deliberately a curated table, not full Unicode TR39: the MVP targets the
//! substitutions actually seen in crypto/job scams (Cyrillic/Greek lookalikes,
//! I/l/1 games, rn→m). Coverage grows by data, and misses fold to "no match"
//! — never to a false claim of safety.

/// Fold a string to a canonical skeleton: lowercase, confusables mapped to
/// their ASCII target, multi-char tricks collapsed.
pub fn skeleton(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            // Cyrillic lookalikes
            'а' => out.push('a'),
            'е' => out.push('e'),
            'о' => out.push('o'),
            'р' => out.push('p'),
            'с' => out.push('c'),
            'х' => out.push('x'),
            'у' => out.push('y'),
            'і' => out.push('i'),
            'ѕ' => out.push('s'),
            'ԁ' => out.push('d'),
            'ց' => out.push('g'),
            'һ' => out.push('h'),
            'ⅼ' | 'ӏ' => out.push('l'),
            // Greek lookalikes
            'ο' => out.push('o'),
            'ν' => out.push('v'),
            'α' => out.push('a'),
            'ε' => out.push('e'),
            'τ' => out.push('t'),
            'ι' => out.push('i'),
            'κ' => out.push('k'),
            'ρ' => out.push('p'),
            // ASCII games: capital I and pipe read as lowercase L in most
            // sans-serif UI fonts; digits standing in for letters.
            'I' | '|' => out.push('l'),
            '1' => out.push('l'),
            '0' => out.push('o'),
            '3' => out.push('e'),
            '5' => out.push('s'),
            '@' => out.push('a'),
            '$' => out.push('s'),
            // Zero-width and joiner characters vanish.
            '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}' => {}
            _ => {
                for lc in c.to_lowercase() {
                    out.push(lc);
                }
            }
        }
    }
    // Multi-character tricks after single-char folding.
    out.replace("rn", "m").replace("vv", "w")
}

/// Levenshtein distance with an early cutoff (we only care about ≤ 2).
pub fn edit_distance_capped(a: &str, b: &str, cap: usize) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > cap {
        return cap + 1;
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        let mut row_min = cur[0];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
            row_min = row_min.min(cur[j]);
        }
        if row_min > cap {
            return cap + 1;
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saylor_uppercase_i_folds_to_saylor() {
        // The concept spec's example: "Michael SayIor" (uppercase I).
        assert_eq!(skeleton("Michael SayIor"), skeleton("Michael Saylor"));
    }

    #[test]
    fn cyrillic_apple_folds() {
        assert_eq!(skeleton("аррle"), "apple"); // Cyrillic а, р, р
    }

    #[test]
    fn rn_reads_as_m() {
        assert_eq!(skeleton("rnetamask"), "metamask");
    }

    #[test]
    fn distance_cap_works() {
        assert_eq!(edit_distance_capped("breezyhr", "breezy", 2), 2);
        assert_eq!(edit_distance_capped("uniswap", "uniswap", 2), 0);
        assert!(edit_distance_capped("completely", "different", 2) > 2);
    }
}
