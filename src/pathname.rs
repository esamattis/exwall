//! The URLPattern pathname subset implemented by mitmwall (including slash-prefix modifiers).
use crate::error::{Result, bail, ensure};

/// A parsed pathname literal, matcher, or delimited token group.
#[derive(Debug)]
enum Token {
    /// Literal pathname text with pattern syntax already unescaped.
    Text(String),
    /// Parameter, wildcard, or regex body with an optional modifier.
    Part(String, Option<char>),
    /// Delimited tokens whose modifier applies to the entire group.
    Group(Vec<Token>, Option<char>),
}

/// A character cursor used to parse mitmwall pathname syntax.
struct Parser {
    chars: Vec<char>,
    pos: usize,
}
impl Parser {
    /// Inspect the next character without consuming it.
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    /// Consume the next character and advance the parser cursor.
    fn next(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    /// Consume an optional repetition or optionality modifier.
    fn modifier(&mut self) -> Option<char> {
        if matches!(self.peek(), Some('?' | '+' | '*')) {
            self.next()
        } else {
            None
        }
    }

    /// Consume and validate an identifier or quoted parameter name.
    fn name(&mut self) -> Result<()> {
        if self.peek() == Some('"') {
            self.next();
            let mut count = 0;
            loop {
                match self.next() {
                    Some('"') => {
                        ensure!(count > 0, "missing parameter name");
                        return Ok(());
                    }
                    Some('\\') => {
                        ensure!(self.next().is_some(), "unfinished escape");
                        count += 1;
                    }
                    Some(_) => count += 1,
                    None => bail!("unterminated quote"),
                }
            }
        }
        ensure!(
            self.peek().is_some_and(|c| c.is_alphabetic() || c == '$' || c == '_'),
            "missing parameter name"
        );
        while self.peek().is_some_and(|c| {
            c.is_alphanumeric() || matches!(c, '$' | '_' | '\u{200c}' | '\u{200d}')
        }) {
            self.next();
        }
        Ok(())
    }

    /// Read a balanced regex group, respecting escapes and character classes.
    fn regex(&mut self) -> Result<String> {
        ensure!(self.next() == Some('('), "expected regex group");
        let mut source = String::new();
        let mut depth = 1;
        let mut class = false;
        while let Some(c) = self.next() {
            match c {
                '\\' => {
                    source.push(c);
                    source.push(self.next().ok_or_else(|| {
                        crate::error::Error::message("unfinished escape".to_string())
                    })?);
                    continue;
                }
                '[' => class = true,
                ']' if class => class = false,
                '(' if !class => depth += 1,
                ')' if !class => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(source);
                    }
                }
                _ => (),
            }
            source.push(c);
        }
        bail!("unterminated regex group")
    }

    /// Parse pathname tokens until input ends or a delimited group closes.
    fn tokens(&mut self, in_group: bool) -> Result<Vec<Token>> {
        let mut tokens = Vec::new();
        let mut literal = String::new();
        while let Some(c) = self.next() {
            let part = match c {
                '\\' => {
                    literal.push(self.next().ok_or_else(|| {
                        crate::error::Error::message("unfinished escape".to_string())
                    })?);
                    continue;
                }
                '}' if in_group => {
                    if !literal.is_empty() {
                        tokens.push(Token::Text(literal));
                    }
                    return Ok(tokens);
                }
                ':' => {
                    self.name()?;
                    let body = if self.peek() == Some('(') {
                        self.regex()?
                    } else {
                        "[^/]+?".into()
                    };
                    Token::Part(body, self.modifier())
                }
                '*' => Token::Part(".*".into(), self.modifier()),
                '(' => {
                    self.pos -= 1;
                    let body = self.regex()?;
                    Token::Part(body, self.modifier())
                }
                '{' => {
                    ensure!(!in_group, "nested group delimiter");
                    let body = self.tokens(true)?;
                    Token::Group(body, self.modifier())
                }
                '}' | '[' | ']' | '+' | '?' => bail!("unexpected {c} at {}", self.pos - 1),
                _ => {
                    literal.push(c);
                    continue;
                }
            };
            if !literal.is_empty() {
                tokens.push(Token::Text(std::mem::take(&mut literal)));
            }
            tokens.push(part);
        }
        ensure!(!in_group, "unterminated delimited group");
        if !literal.is_empty() {
            tokens.push(Token::Text(literal));
        }
        Ok(tokens)
    }
}

/// Convert parsed tokens into regex source with slash-prefix modifiers.
fn source(tokens: &[Token], automatic_prefix: bool) -> String {
    let mut output = String::new();
    for (i, token) in tokens.iter().enumerate() {
        match token {
            Token::Text(text) => output.push_str(&regex::escape(text)),
            Token::Group(tokens, modifier) => {
                output.push_str(&modified(&source(tokens, false), *modifier, ""))
            }
            Token::Part(body, modifier) => {
                let prefix = if automatic_prefix
                    && modifier.is_some()
                    && i > 0
                    && matches!(&tokens[i-1], Token::Text(t) if t.ends_with('/'))
                {
                    output.pop();
                    "/"
                } else {
                    ""
                };
                output.push_str(&modified(body, *modifier, prefix));
            }
        }
    }
    output
}

/// Apply a matcher modifier to the body and its optional slash prefix.
fn modified(body: &str, modifier: Option<char>, prefix: &str) -> String {
    let combined = format!("{}(?:{body})", regex::escape(prefix));
    match modifier {
        Some(c) => format!("(?:{combined}){c}"),
        None => combined,
    }
}

/// Compile pathname syntax into a regex that matches the entire pathname.
pub fn compile(pattern: &str) -> Result<fancy_regex::Regex> {
    ensure!(!pattern.contains("://"), "pathname_pattern must be a URL path, not a full URL");
    let body = if !pattern.chars().any(|c| ":*{}()\\".contains(c)) {
        regex::escape(pattern)
    } else {
        source(
            &Parser {
                chars: pattern.chars().collect(),
                pos: 0,
            }
            .tokens(false)?,
            true,
        )
    };
    Ok(fancy_regex::Regex::new(&format!("\\A(?:{body})\\z"))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Check mitmwall pathname examples and malformed-pattern rejection.
    #[test]
    fn source_compatible_patterns() {
        for (pattern, yes, no) in [
            ("/books/:id?", vec!["/books", "/books/123"], vec!["/books/"]),
            ("/books/:id+", vec!["/books/123/456"], vec!["/books", "/books/"]),
            ("/authors/:id*", vec!["/authors", "/authors/123/456"], vec!["/authors/"]),
            ("/users{/me}?", vec!["/users", "/users/me"], vec!["/users/"]),
            ("/login/*", vec!["/login/", "/login/a/b"], vec!["/login"]),
            ("/files/*path", vec!["/files/path", "/files/nested/path"], vec!["/files/file"]),
            (r"/books/:id(\d+)", vec!["/books/123"], vec!["/books/abc"]),
            ("/(foo|bar)", vec!["/foo", "/bar"], vec!["/baz"]),
            ("/books{/}?", vec!["/books", "/books/"], vec!["/books//"]),
            ("/registry+json", vec!["/registry+json"], vec!["/registry-json"]),
            (r"/literal\:value\{x\}", vec!["/literal:value{x}"], vec![]),
            ("/users/:\"user-id\"", vec!["/users/123"], vec!["/users/"]),
        ] {
            let re = compile(pattern).unwrap();
            for path in yes {
                assert!(re.is_match(path).unwrap(), "{pattern}: {path}");
            }
            for path in no {
                assert!(!re.is_match(path).unwrap(), "{pattern}: {path}");
            }
        }
        for pattern in
            ["/users/:/", "/users{{/me}?}", "/users/:\"id", "https://example.com/a", "/:id(["]
        {
            assert!(compile(pattern).is_err(), "{pattern}");
        }
    }
}
