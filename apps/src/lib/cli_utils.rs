pub trait FormatHelp {
    fn wrap_lines(self) -> String;
}

const MAX_LETTERS: usize = 80;

impl FormatHelp for &str {
    fn wrap_lines(self) -> String {
        let (mut result, _) = self.split_whitespace().fold(
            (String::new(), 0),
            |(mut result, mut line_len), word| {
                let word_length = word.chars().count();
                line_len += word_length;
                if !result.is_empty() && line_len > MAX_LETTERS {
                    result.pop(); //remove space
                    result.push('\n');
                    line_len = word_length + 1;
                }
                result.push_str(word);
                result.push(' ');
                line_len += 1; // add space
                (result, line_len)
            },
        );
        result.pop(); //remove space
        result
    }
}

#[cfg(test)]
mod test {
    use crate::cli_utils::{FormatHelp, MAX_LETTERS};

    #[test]
    fn test_wrap() {
        let short_text = "Hello word";
        assert_eq!(short_text, "Hello word".wrap_lines());
        let eighty_letter_text = "In the heart of a bustling city, where \
                                  skyscraper touched the sky and neon light";
        assert_eq!(eighty_letter_text.len(), MAX_LETTERS);
        assert_eq!(
            eighty_letter_text.wrap_lines(),
            "In the heart of a bustling city, where skyscraper touched the \
             sky and neon light"
        );
        let extremely_long_text =
            "In the heart of a bustling city, where skyscrapers touched the \
             sky and neon lights painted the streets, there lived an \
             enigmatic antique shop owner named Mr. Evergreen. His shop, \
             nestled between modern boutiques, held treasures from eras long \
             forgotten";
        assert_eq!(
            extremely_long_text.wrap_lines(),
            "In the heart of a bustling city, where skyscrapers touched the \
             sky and neon
lights painted the streets, there lived an enigmatic antique shop owner named
Mr. Evergreen. His shop, nestled between modern boutiques, held treasures from
eras long forgotten"
        );
    }
}
