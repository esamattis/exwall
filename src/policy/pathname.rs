//! The URLPattern pathname subset implemented by mitmwall (including slash-prefix modifiers).

use thiserror::Error;

/// A malformed `pathname_pattern`.
#[derive(Debug, Error)]
pub enum PathnameError {
    /// The pattern is a full URL rather than a path.
    #[error("pathname_pattern must be a URL path, not a full URL")]
    FullUrl,
    /// A `:` parameter has no name.
    #[error("missing parameter name")]
    MissingName,
    /// A backslash ends the pattern.
    #[error("unfinished escape")]
    UnfinishedEscape,
    /// A quoted parameter name is not closed.
    #[error("unterminated quote")]
    UnterminatedQuote,
    /// A regex group was expected but not found.
    #[error("expected regex group")]
    ExpectedRegexGroup,
    /// A regex group is not closed.
    #[error("unterminated regex group")]
    UnterminatedRegexGroup,
    /// A `{` group appears inside another group.
    #[error("nested group delimiter")]
    NestedGroup,
    /// A `{` group is not closed.
    #[error("unterminated delimited group")]
    UnterminatedGroup,
    /// A reserved character appears where it is not allowed.
    #[error("unexpected {character} at {position}")]
    Unexpected {
        /// The offending character.
        character: char,
        /// Its zero-based character position.
        position: usize,
    },
    /// The generated regular expression failed to compile.
    #[error("invalid pathname regex")]
    Regex(#[source] Box<fancy_regex::Error>),
}

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
    /// The pattern's characters.
    chars: Vec<char>,
    /// The index of the next unread character.
    pos: usize,
}

impl Parser {
    /// Inspect the next character without consuming it.
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    /// Consume the next character and advance the parser cursor.
    fn next(&mut self) -> Option<char> {
        let character = self.peek()?;
        self.pos += 1;
        Some(character)
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
    fn name(&mut self) -> Result<(), PathnameError> {
        if self.peek() == Some('"') {
            self.next();
            let mut count = 0;
            loop {
                match self.next() {
                    Some('"') => {
                        if count == 0 {
                            return Err(PathnameError::MissingName);
                        }
                        return Ok(());
                    }
                    Some('\\') => {
                        if self.next().is_none() {
                            return Err(PathnameError::UnfinishedEscape);
                        }
                        count += 1;
                    }
                    Some(_) => count += 1,
                    None => return Err(PathnameError::UnterminatedQuote),
                }
            }
        }
        let starts_name = self.peek().is_some_and(|c| c.is_alphabetic() || c == '$' || c == '_');
        if !starts_name {
            return Err(PathnameError::MissingName);
        }
        while self.peek().is_some_and(|c| {
            c.is_alphanumeric() || matches!(c, '$' | '_' | '\u{200c}' | '\u{200d}')
        }) {
            self.next();
        }
        Ok(())
    }

    /// Read a balanced regex group, respecting escapes and character classes.
    fn regex(&mut self) -> Result<String, PathnameError> {
        if self.next() != Some('(') {
            return Err(PathnameError::ExpectedRegexGroup);
        }
        let mut source = String::new();
        let mut depth = 1;
        let mut class = false;
        while let Some(character) = self.next() {
            match character {
                '\\' => {
                    source.push(character);
                    source.push(self.next().ok_or(PathnameError::UnfinishedEscape)?);
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
            source.push(character);
        }
        Err(PathnameError::UnterminatedRegexGroup)
    }

    /// Parse pathname tokens until input ends or a delimited group closes.
    fn tokens(&mut self, in_group: bool) -> Result<Vec<Token>, PathnameError> {
        let mut tokens = Vec::new();
        let mut literal = String::new();
        while let Some(character) = self.next() {
            let part = match character {
                '\\' => {
                    literal.push(self.next().ok_or(PathnameError::UnfinishedEscape)?);
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
                    if in_group {
                        return Err(PathnameError::NestedGroup);
                    }
                    let body = self.tokens(true)?;
                    Token::Group(body, self.modifier())
                }
                '}' | '[' | ']' | '+' | '?' => {
                    return Err(PathnameError::Unexpected {
                        character,
                        position: self.pos - 1,
                    });
                }
                _ => {
                    literal.push(character);
                    continue;
                }
            };
            if !literal.is_empty() {
                tokens.push(Token::Text(std::mem::take(&mut literal)));
            }
            tokens.push(part);
        }
        if in_group {
            return Err(PathnameError::UnterminatedGroup);
        }
        if !literal.is_empty() {
            tokens.push(Token::Text(literal));
        }
        Ok(tokens)
    }
}

/// Convert parsed tokens into regex source with slash-prefix modifiers.
fn source(tokens: &[Token], automatic_prefix: bool) -> String {
    let mut output = String::new();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Text(text) => output.push_str(&regex::escape(text)),
            Token::Group(tokens, modifier) => {
                output.push_str(&modified(&source(tokens, false), *modifier, ""));
            }
            Token::Part(body, modifier) => {
                let follows_slash = index > 0
                    && matches!(&tokens[index - 1], Token::Text(text) if text.ends_with('/'));
                let prefix = if automatic_prefix && modifier.is_some() && follows_slash {
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
        Some(character) => format!("(?:{combined}){character}"),
        None => combined,
    }
}

/// Compile pathname syntax into regex source that matches the entire pathname.
pub fn compile_source(pattern: &str) -> Result<String, PathnameError> {
    if pattern.contains("://") {
        return Err(PathnameError::FullUrl);
    }
    let body = if !pattern.chars().any(|c| ":*{}()\\".contains(c)) {
        regex::escape(pattern)
    } else {
        let mut parser = Parser {
            chars: pattern.chars().collect(),
            pos: 0,
        };
        source(&parser.tokens(false)?, true)
    };
    Ok(format!("\\A(?:{body})\\z"))
}

/// Compile pathname syntax into a regex that matches the entire pathname.
pub fn compile(pattern: &str) -> Result<fancy_regex::Regex, PathnameError> {
    let source = compile_source(pattern)?;
    fancy_regex::Regex::new(&source).map_err(|error| PathnameError::Regex(Box::new(error)))
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

    /// Specific malformed patterns report specific, typed errors.
    #[test]
    fn reports_typed_errors() {
        assert!(matches!(compile("https://x/"), Err(PathnameError::FullUrl)));
        assert!(matches!(compile("/a{/b"), Err(PathnameError::UnterminatedGroup)));
        assert!(matches!(compile("/a/(b"), Err(PathnameError::UnterminatedRegexGroup)));
        assert!(matches!(
            compile("/:a]"),
            Err(PathnameError::Unexpected {
                character: ']',
                position: 3
            })
        ));
    }
}
