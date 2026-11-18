//! Project naming.
use crate::error::{Error, Result};

pub(crate) fn project_name(value: &str) -> Result<(String, String)> {
    let display = value.trim();
    if !(2..=40).contains(&display.chars().count()) || display.chars().any(char::is_control) {
        return Err(Error::invalid(
            "project name must contain 2–40 printable characters",
        ));
    }
    let mut slug = String::new();
    for c in display.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_end_matches('-').to_owned();
    if slug.is_empty() {
        return Err(Error::invalid(
            "project name must contain an ASCII letter or number",
        ));
    }
    Ok((display.to_owned(), slug))
}
