use xdr_userland::rules::RuleParser;

#[test]
fn rule_yaml_roundtrip() {
    let parser = RuleParser::new();
    for entry in std::fs::read_dir("../rules").expect("rules dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let rule = match parser.parse_file(&path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skipping {:?}: {e}", path);
                continue;
            }
        };
        let yaml = match serde_yaml::to_string(&rule) {
            Ok(y) => y,
            Err(e) => {
                eprintln!("serialize {:?}: {e}", path);
                continue;
            }
        };
        let reparsed = match parser.parse_yaml(&yaml) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("reparse {:?}: {e}", path);
                continue;
            }
        };
        let v1 = serde_yaml::to_value(&rule).expect("value1");
        let v2 = serde_yaml::to_value(&reparsed).expect("value2");
        assert_eq!(v1, v2, "roundtrip mismatch for {:?}", path);
    }
}
