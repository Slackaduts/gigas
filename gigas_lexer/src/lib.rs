use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::iter::Peekable;
use std::str::Chars;

// Load registers from external file at compile time
static REGISTER_LIST: &str = include_str!(".\\res\\x86_registers.txt");

// Create a static HashSet containing all registers
static X86_REGISTERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    REGISTER_LIST
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
});

// Pre-populated hash set for mnemonics - could also be moved to a file
static X86_MNEMONICS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut m = HashSet::new();
    m.extend([
        "mov", "add", "sub", "push", "pop", "jmp", "call", "ret", "lea", "cmp", "test", "and",
        "or", "xor", "not", "neg", "inc", "dec", "mul", "div", "shl", "shr", "sal", "sar", "rol",
        "ror", "rcl", "rcr",
    ]);
    // Add more instructions as needed
    m
});

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Mnemonic(String),
    Register(String),
    Immediate(i64),
    Variable(String),
    Symbol(char), // Catch-all for simple symbols ([,]:+-)
    Label(String),
    Comment(String),
    Directive(String),
    Newline,
    EOF,
}

pub struct Lexer<'a> {
    input: Peekable<Chars<'a>>,
    line: usize,
    column: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Lexer {
            input: input.chars().peekable(),
            line: 1,
            column: 1,
        }
    }

    fn advance(&mut self) -> Option<char> {
        let c = self.input.next()?;
        if c == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(c)
    }

    fn peek(&mut self) -> Option<&char> {
        self.input.peek()
    }

    fn read_while<F>(&mut self, predicate: F) -> String
    where
        F: Fn(char) -> bool,
    {
        let mut result = String::new();
        while let Some(&c) = self.peek() {
            if !predicate(c) {
                break;
            }
            result.push(c);
            self.advance();
        }
        result
    }

    fn read_identifier(&mut self) -> Token {
        let id = self.read_while(|c| c.is_alphanumeric() || c == '_');

        // Check for label definition (ending with colon)
        if let Some(&':') = self.peek() {
            self.advance(); // Consume the colon
            return Token::Label(id);
        }

        if id.starts_with('.') {
            // This is an assembler directive
            Token::Directive(id)
        } else if X86_REGISTERS.contains(id.as_str()) {
            Token::Register(id)
        } else if X86_MNEMONICS.contains(id.as_str()) {
            Token::Mnemonic(id)
        } else {
            // Assume it's a label reference or unknown identifier
            Token::Label(id)
        }
    }

    fn read_number(&mut self) -> Token {
        let mut value = String::new();
        let mut base = 10;

        // Check for hex/binary prefix
        if let Some(&'0') = self.peek() {
            self.advance();
            value.push('0');
            if let Some(&c) = self.peek() {
                match c {
                    'x' | 'X' => {
                        self.advance();
                        value.push(c);
                        base = 16;
                    }
                    'b' | 'B' => {
                        self.advance();
                        value.push(c);
                        base = 2;
                    }
                    _ => {}
                }
            }
        }

        value.push_str(&self.read_while(|c| match base {
            10 => c.is_digit(10),
            16 => c.is_digit(16) || ('a'..='f').contains(&c) || ('A'..='F').contains(&c),
            2 => c == '0' || c == '1',
            _ => unreachable!(),
        }));

        // Parse the number (simplified error handling)
        let parsed = if base == 10 {
            value.parse::<i64>()
        } else if base == 16 {
            i64::from_str_radix(&value.trim_start_matches("0x").trim_start_matches("0X"), 16)
        } else {
            // base == 2
            i64::from_str_radix(&value.trim_start_matches("0b").trim_start_matches("0B"), 2)
        };

        match parsed {
            Ok(n) => Token::Immediate(n),
            Err(_) => Token::Immediate(0), // Default in case of error
        }
    }

    fn read_variable(&mut self) -> Token {
        self.advance(); // Skip $
        if let Some(&'{') = self.peek() {
            self.advance(); // Skip {
            let name = self.read_while(|c| c != '}');
            self.advance(); // Skip }
            Token::Variable(name)
        } else {
            let name = self.read_while(|c| c.is_alphanumeric() || c == '_');
            Token::Variable(name)
        }
    }

    fn read_comment(&mut self) -> Token {
        self.advance(); // Skip semicolon
        Token::Comment(self.read_while(|c| c != '\n'))
    }

    pub fn next_token(&mut self) -> Option<Token> {
        // Skip whitespace (but not newlines)
        self.read_while(|c| c.is_whitespace() && c != '\n');

        match self.peek() {
            None => Some(Token::EOF),
            Some(&c) => {
                match c {
                    '\n' => {
                        self.advance();
                        Some(Token::Newline)
                    }
                    ';' => Some(self.read_comment()),
                    '$' => Some(self.read_variable()),
                    '0'..='9' => Some(self.read_number()),
                    '[' | ']' | ',' | '+' | '-' | '*' => {
                        let symbol = self.advance().unwrap();
                        Some(Token::Symbol(symbol))
                    }
                    _ if c.is_alphabetic() || c == '_' || c == '.' => Some(self.read_identifier()),
                    _ => {
                        self.advance(); // Skip unrecognized
                        self.next_token() // Try again
                    }
                }
            }
        }
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = Token;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_token() {
            None => None,
            Some(Token::EOF) => None,
            Some(token) => Some(token),
        }
    }
}

// Simple test function to demonstrate usage
pub fn tokenize(input: &str) -> Vec<Token> {
    Lexer::new(input).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_instruction() {
        let tokens = tokenize("mov rax, 42");
        assert_eq!(tokens[0], Token::Mnemonic("mov".to_string()));
        assert_eq!(tokens[1], Token::Register("rax".to_string()));
        assert_eq!(tokens[2], Token::Symbol(','));
        assert_eq!(tokens[3], Token::Immediate(42));
    }

    #[test]
    fn test_variable_substitution() {
        let tokens = tokenize("add rax, ${my_var}");
        assert_eq!(tokens[0], Token::Mnemonic("add".to_string()));
        assert_eq!(tokens[1], Token::Register("rax".to_string()));
        assert_eq!(tokens[2], Token::Symbol(','));
        assert_eq!(tokens[3], Token::Variable("my_var".to_string()));
    }

    #[test]
    fn test_comment() {
        let tokens = tokenize("push rbp ; Setup stack frame");
        assert_eq!(tokens[0], Token::Mnemonic("push".to_string()));
        assert_eq!(tokens[1], Token::Register("rbp".to_string()));
        assert_eq!(tokens[2], Token::Comment(" Setup stack frame".to_string()));
    }
}
