use thiserror::Error;

// SCIM Filter parsing structures, now public for sharing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimOperator {
    Eq, // equals
    Ne, // not equals
    Co, // contains
    Sw, // starts with
    Ew, // ends with
    Pr, // present (has value)
    Gt, // greater than
    Ge, // greater than or equal
    Lt, // less than
    Le, // less than or equal
}

#[derive(Debug, Clone)]
pub struct ScimFilter {
    pub attribute: String,
    pub operator: ScimOperator,
    pub value: Option<String>,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ScimFilterError {
    #[error("Invalid filter syntax")]
    InvalidSyntax,
    #[error("Unsupported operator: {0}")]
    UnsupportedOperator(String),
    #[error("Invalid attribute: {0}")]
    InvalidAttribute(String),
    #[error("Filter too long (max 500 characters)")]
    FilterTooLong,
}

pub fn parse_scim_filter(filter: &str) -> Result<ScimFilter, ScimFilterError> {
    // This is a simplified parser. A production implementation would need to handle
    // complex logical operators (AND, OR) and grouping.
    if filter.len() > 500 {
        return Err(ScimFilterError::FilterTooLong);
    }

    let parts: Vec<&str> = filter.split_whitespace().collect();
    if parts.len() < 2 || parts.len() > 3 {
        return Err(ScimFilterError::InvalidSyntax);
    }

    let attribute = parts[0].to_string();
    let operator_str = parts[1];
    let value = parts.get(2).map(|v| v.trim_matches('"').to_string());

    let operator = match operator_str.to_lowercase().as_str() {
        "eq" => ScimOperator::Eq,
        "ne" => ScimOperator::Ne,
        "co" => ScimOperator::Co,
        "sw" => ScimOperator::Sw,
        "ew" => ScimOperator::Ew,
        "pr" => ScimOperator::Pr,
        _ => return Err(ScimFilterError::UnsupportedOperator(operator_str.to_string())),
    };

    if operator != ScimOperator::Pr && value.is_none() {
        return Err(ScimFilterError::InvalidSyntax);
    }

    Ok(ScimFilter { attribute, operator, value })
}
