use thiserror::Error;

#[derive(Error, Debug)]
pub enum RC5Error {
    #[error("invalid key length")]
    InvalidKeyLength,

    #[error("invalid plaintext length")]
    InvalidPlainTextLength,
    
    #[error("invalid cyphertext length")]
    InvalidCypherTextLength,
}