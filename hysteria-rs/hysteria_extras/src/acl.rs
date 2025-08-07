//! Access Control List (ACL) for Hysteria 2
//!
//! This module provides ACL functionality to control which connections
//! are allowed, blocked, or routed through different outbounds.

use std::net::IpAddr;
use std::str::FromStr;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use regex::Regex;
use lru::LruCache;
use std::sync::Mutex;
use crate::{ExtrasError, Result};

/// Protocol type for ACL rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Any,
}

impl FromStr for Protocol {
    type Err = ExtrasError;
    
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            "any" | "*" => Ok(Protocol::Any),
            _ => Err(ExtrasError::AclError(format!("Invalid protocol: {}", s))),
        }
    }
}

/// ACL rule action
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Allow(String),  // Allow with outbound name
    Block,          // Block the connection
    Direct,         // Direct connection
}

impl FromStr for Action {
    type Err = ExtrasError;
    
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "block" | "reject" => Ok(Action::Block),
            "direct" => Ok(Action::Direct),
            outbound => Ok(Action::Allow(outbound.to_string())),
        }
    }
}

/// Address matcher for ACL rules
#[derive(Debug, Clone)]
pub enum AddressMatcher {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(Regex),
    Ipv4Cidr(Ipv4Cidr),
    Ipv6Cidr(Ipv6Cidr),
    GeoIp(String),
    Any,
}

impl AddressMatcher {
    /// Check if an address matches this matcher
    pub fn matches(&self, addr: &str, ip: Option<IpAddr>) -> bool {
        match self {
            AddressMatcher::Domain(domain) => addr == domain,
            AddressMatcher::DomainSuffix(suffix) => {
                addr.ends_with(suffix) && (addr.len() == suffix.len() || addr.ends_with(&format!(".{}", suffix)))
            }
            AddressMatcher::DomainKeyword(keyword) => addr.contains(keyword),
            AddressMatcher::DomainRegex(regex) => regex.is_match(addr),
            AddressMatcher::Ipv4Cidr(cidr) => {
                if let Some(IpAddr::V4(ipv4)) = ip {
                    cidr.contains(&ipv4)
                } else {
                    false
                }
            }
            AddressMatcher::Ipv6Cidr(cidr) => {
                if let Some(IpAddr::V6(ipv6)) = ip {
                    cidr.contains(&ipv6)
                } else {
                    false
                }
            }
            AddressMatcher::GeoIp(_country) => {
                // TODO: Implement GeoIP lookup
                false
            }
            AddressMatcher::Any => true,
        }
    }
}

/// Port matcher for ACL rules
#[derive(Debug, Clone)]
pub enum PortMatcher {
    Single(u16),
    Range(u16, u16),
    Any,
}

impl PortMatcher {
    /// Check if a port matches this matcher
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortMatcher::Single(p) => port == *p,
            PortMatcher::Range(start, end) => port >= *start && port <= *end,
            PortMatcher::Any => true,
        }
    }
}

impl FromStr for PortMatcher {
    type Err = ExtrasError;
    
    fn from_str(s: &str) -> Result<Self> {
        if s == "*" || s.is_empty() {
            return Ok(PortMatcher::Any);
        }
        
        if s.contains('-') {
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() != 2 {
                return Err(ExtrasError::AclError(format!("Invalid port range: {}", s)));
            }
            let start = parts[0].parse::<u16>()
                .map_err(|_| ExtrasError::AclError(format!("Invalid port: {}", parts[0])))?;
            let end = parts[1].parse::<u16>()
                .map_err(|_| ExtrasError::AclError(format!("Invalid port: {}", parts[1])))?;
            Ok(PortMatcher::Range(start, end))
        } else {
            let port = s.parse::<u16>()
                .map_err(|_| ExtrasError::AclError(format!("Invalid port: {}", s)))?;
            Ok(PortMatcher::Single(port))
        }
    }
}

/// ACL rule
#[derive(Debug, Clone)]
pub struct Rule {
    pub protocol: Protocol,
    pub address: AddressMatcher,
    pub port: PortMatcher,
    pub action: Action,
}

impl Rule {
    /// Create a new ACL rule
    pub fn new(protocol: Protocol, address: AddressMatcher, port: PortMatcher, action: Action) -> Self {
        Self { protocol, address, port, action }
    }
    
    /// Check if this rule matches the given connection
    pub fn matches(&self, protocol: Protocol, addr: &str, port: u16, ip: Option<IpAddr>) -> bool {
        // Check protocol
        if self.protocol != Protocol::Any && self.protocol != protocol {
            return false;
        }
        
        // Check address
        if !self.address.matches(addr, ip) {
            return false;
        }
        
        // Check port
        self.port.matches(port)
    }
}

/// ACL rule set
#[derive(Debug)]
pub struct RuleSet {
    rules: Vec<Rule>,
    cache: Mutex<LruCache<String, Action>>,
}

impl RuleSet {
    /// Create a new rule set
    pub fn new(cache_size: usize) -> Self {
        Self {
            rules: Vec::new(),
            cache: Mutex::new(LruCache::new(std::num::NonZeroUsize::new(cache_size).unwrap_or(std::num::NonZeroUsize::new(1024).unwrap()))),
        }
    }
    
    /// Add a rule to the set
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }
    
    /// Find the action for a given connection
    pub fn find_action(&self, protocol: Protocol, addr: &str, port: u16, ip: Option<IpAddr>) -> Option<Action> {
        // Create cache key
        let cache_key = format!("{}:{}:{}", 
            match protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
                Protocol::Any => "any",
            },
            addr,
            port
        );
        
        // Check cache first
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(action) = cache.get(&cache_key) {
                return Some(action.clone());
            }
        }
        
        // Find matching rule
        for rule in &self.rules {
            if rule.matches(protocol, addr, port, ip) {
                let action = rule.action.clone();
                
                // Cache the result
                {
                    let mut cache = self.cache.lock().unwrap();
                    cache.put(cache_key, action.clone());
                }
                
                return Some(action);
            }
        }
        
        None
    }
    
    /// Clear the cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }
}

/// ACL engine that manages rule sets and outbounds
#[derive(Debug)]
pub struct AclEngine {
    rule_set: RuleSet,
    default_action: Action,
}

impl AclEngine {
    /// Create a new ACL engine
    pub fn new(cache_size: usize, default_action: Action) -> Self {
        Self {
            rule_set: RuleSet::new(cache_size),
            default_action,
        }
    }
    
    /// Add a rule to the engine
    pub fn add_rule(&mut self, rule: Rule) {
        self.rule_set.add_rule(rule);
    }
    
    /// Evaluate a connection and return the action
    pub fn evaluate(&self, protocol: Protocol, addr: &str, port: u16, ip: Option<IpAddr>) -> Action {
        self.rule_set.find_action(protocol, addr, port, ip)
            .unwrap_or_else(|| self.default_action.clone())
    }
}

/// Parse ACL rules from text
pub fn parse_rules(text: &str) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();
    
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        let rule = parse_rule(line)?;
        rules.push(rule);
    }
    
    Ok(rules)
}

/// Parse a single ACL rule
fn parse_rule(line: &str) -> Result<Rule> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(ExtrasError::AclError(format!("Invalid rule format: {}", line)));
    }
    
    let action = Action::from_str(parts[0])?;
    let protocol = if parts.len() > 2 {
        Protocol::from_str(parts[2])?
    } else {
        Protocol::Any
    };
    
    // Parse address and port
    let addr_port = parts[1];
    let (addr_str, port_str) = if let Some(colon_pos) = addr_port.rfind(':') {
        let addr = &addr_port[..colon_pos];
        let port = &addr_port[colon_pos + 1..];
        (addr, port)
    } else {
        (addr_port, "*")
    };
    
    let address = parse_address_matcher(addr_str)?;
    let port = PortMatcher::from_str(port_str)?;
    
    Ok(Rule::new(protocol, address, port, action))
}

/// Parse address matcher from string
fn parse_address_matcher(s: &str) -> Result<AddressMatcher> {
    if s == "*" {
        return Ok(AddressMatcher::Any);
    }
    
    // Try to parse as IP/CIDR
    if let Ok(ipv4_cidr) = Ipv4Cidr::from_str(s) {
        return Ok(AddressMatcher::Ipv4Cidr(ipv4_cidr));
    }
    
    if let Ok(ipv6_cidr) = Ipv6Cidr::from_str(s) {
        return Ok(AddressMatcher::Ipv6Cidr(ipv6_cidr));
    }
    
    // Check for special prefixes
    if s.starts_with("suffix:") {
        return Ok(AddressMatcher::DomainSuffix(s[7..].to_string()));
    }
    
    if s.starts_with("keyword:") {
        return Ok(AddressMatcher::DomainKeyword(s[8..].to_string()));
    }
    
    if s.starts_with("regex:") {
        let regex = Regex::new(&s[6..])
            .map_err(|e| ExtrasError::AclError(format!("Invalid regex: {}", e)))?;
        return Ok(AddressMatcher::DomainRegex(regex));
    }
    
    if s.starts_with("geoip:") {
        return Ok(AddressMatcher::GeoIp(s[6..].to_string()));
    }
    
    // Default to domain match
    Ok(AddressMatcher::Domain(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protocol_parsing() {
        assert_eq!(Protocol::from_str("tcp").unwrap(), Protocol::Tcp);
        assert_eq!(Protocol::from_str("UDP").unwrap(), Protocol::Udp);
        assert_eq!(Protocol::from_str("any").unwrap(), Protocol::Any);
        assert!(Protocol::from_str("invalid").is_err());
    }
    
    #[test]
    fn test_action_parsing() {
        assert_eq!(Action::from_str("block").unwrap(), Action::Block);
        assert_eq!(Action::from_str("direct").unwrap(), Action::Direct);
        assert_eq!(Action::from_str("proxy1").unwrap(), Action::Allow("proxy1".to_string()));
    }
    
    #[test]
    fn test_port_matcher() {
        let single = PortMatcher::from_str("80").unwrap();
        assert!(single.matches(80));
        assert!(!single.matches(443));
        
        let range = PortMatcher::from_str("8000-9000").unwrap();
        assert!(range.matches(8080));
        assert!(!range.matches(7000));
        
        let any = PortMatcher::from_str("*").unwrap();
        assert!(any.matches(80));
        assert!(any.matches(443));
    }
    
    #[test]
    fn test_address_matcher() {
        let domain = AddressMatcher::Domain("example.com".to_string());
        assert!(domain.matches("example.com", None));
        assert!(!domain.matches("test.example.com", None));
        
        let suffix = AddressMatcher::DomainSuffix("example.com".to_string());
        assert!(suffix.matches("example.com", None));
        assert!(suffix.matches("test.example.com", None));
        assert!(!suffix.matches("notexample.com", None));
    }
    
    #[test]
    fn test_rule_matching() {
        let rule = Rule::new(
            Protocol::Tcp,
            AddressMatcher::Domain("example.com".to_string()),
            PortMatcher::Single(80),
            Action::Direct,
        );
        
        assert!(rule.matches(Protocol::Tcp, "example.com", 80, None));
        assert!(!rule.matches(Protocol::Udp, "example.com", 80, None));
        assert!(!rule.matches(Protocol::Tcp, "test.com", 80, None));
        assert!(!rule.matches(Protocol::Tcp, "example.com", 443, None));
    }
    
    #[test]
    fn test_acl_engine() {
        let mut engine = AclEngine::new(100, Action::Direct);
        
        engine.add_rule(Rule::new(
            Protocol::Any,
            AddressMatcher::Domain("blocked.com".to_string()),
            PortMatcher::Any,
            Action::Block,
        ));
        
        engine.add_rule(Rule::new(
            Protocol::Tcp,
            AddressMatcher::DomainSuffix("proxy.com".to_string()),
            PortMatcher::Any,
            Action::Allow("proxy1".to_string()),
        ));
        
        // Test blocked domain
        let action = engine.evaluate(Protocol::Tcp, "blocked.com", 80, None);
        assert_eq!(action, Action::Block);
        
        // Test proxy domain
        let action = engine.evaluate(Protocol::Tcp, "test.proxy.com", 443, None);
        assert_eq!(action, Action::Allow("proxy1".to_string()));
        
        // Test default action
        let action = engine.evaluate(Protocol::Tcp, "unknown.com", 80, None);
        assert_eq!(action, Action::Direct);
    }
}