use fenders_egress::{DeniedRange, Origin, PublicTargets, is_public_v4};

#[test]
fn exact_origin_normalization_rejects_url_ambiguity() {
    for input in [
        "HTTPS://API.Example.com",
        "https://api.example.com/",
        "https://api.example.com:0443",
    ] {
        assert_eq!(
            Origin::public_https(input).unwrap().to_string(),
            "https://api.example.com:443"
        );
    }
    assert_eq!(
        Origin::public_https("https://1.1.1.1:8443")
            .unwrap()
            .authority(),
        "1.1.1.1:8443"
    );
    for input in [
        "http://api.example.com",
        "https://a.test:0",
        "https://a.test:65536",
        "https://a.test:",
        "https://user@a.test",
        "https://user:password@a.test",
        "https://a.test/path",
        "https://a.test//",
        "https://a.test?x",
        "https://a.test/#x",
        "https://a.test.",
        "https://a..test",
        "https://-a.test",
        "https://a_.test",
        "https://*.test",
        "https://a%2etest",
        "https://a.test\\@b.test",
        "https://[::1]",
        "https://[::ffff:127.0.0.1]",
        " https://a.test",
        "https://a.test\n",
        "https://127.1",
        "https://0177.0.0.1",
        "https://2130706433",
        "https://0x7f000001",
        "https://0x7f.0.0.1",
        "https://localhost",
        "https://x.localhost",
        "https://127.0.0.1",
        "https://169.254.169.254",
        "https://é.test",
    ] {
        assert!(Origin::public_https(input).is_err(), "{input}");
    }
    assert!(Origin::parse("http://10.50.0.2:8080").is_ok());
}

#[test]
fn public_policy_denies_special_use_and_operator_management_ranges() {
    for address in [
        "0.0.0.0",
        "0.255.255.255",
        "10.0.0.1",
        "100.64.0.0",
        "100.127.255.255",
        "127.0.0.1",
        "169.254.169.254",
        "168.63.129.16",
        "172.16.0.0",
        "172.31.255.255",
        "192.0.0.9",
        "192.0.2.3",
        "192.31.196.1",
        "192.52.193.1",
        "192.88.99.1",
        "192.168.1.1",
        "192.175.48.1",
        "198.18.0.0",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.0",
        "239.255.255.255",
        "240.0.0.0",
        "255.255.255.255",
    ] {
        assert!(!is_public_v4(address.parse().unwrap()), "{address}");
    }
    for address in [
        "1.1.1.1",
        "8.8.8.8",
        "100.63.255.255",
        "100.128.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "198.17.255.255",
        "198.20.0.0",
        "223.255.255.255",
    ] {
        assert!(is_public_v4(address.parse().unwrap()), "{address}");
    }
    let range = DeniedRange::parse("8.8.8.0/24").unwrap();
    let mut policy = PublicTargets::default();
    let origin = Origin::public_https("https://api.example.com").unwrap();
    assert!(
        policy
            .insert(
                origin.clone(),
                &["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
                &[range]
            )
            .is_err()
    );
    assert!(policy.encode().is_empty());
    assert!(
        policy
            .insert(
                origin,
                &["1.1.1.1".parse().unwrap()],
                &[DeniedRange::parse("0.0.0.0/0").unwrap()]
            )
            .is_err()
    );
    for value in [
        "8.8.8.1/24",
        "8.8.8.0/33",
        "8.8.8.0/-1",
        "8.8.8.0/024",
        "8.8.8.8",
        "::/0",
    ] {
        assert!(DeniedRange::parse(value).is_err(), "{value}");
    }
}

#[test]
fn pinned_map_is_bounded_exact_and_rejects_mixed_rebinding_answers() {
    let wire = "https://api.example.com:443=1.1.1.1,8.8.8.8;https://other.example.com:8443=9.9.9.9";
    let policy = PublicTargets::parse(wire).unwrap();
    assert_eq!(policy.encode(), wire);
    let origin = Origin::public_https("https://API.EXAMPLE.COM/").unwrap();
    assert_eq!(
        policy
            .get(&origin)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["1.1.1.1:443", "8.8.8.8:443"]
    );
    assert!(
        policy
            .get(&Origin::public_https("https://api.example.com:8443").unwrap())
            .is_none()
    );
    for invalid in [
        "https://api.example.com=1.1.1.1",
        "https://API.example.com:443=1.1.1.1",
        "https://api.example.com:443=",
        "https://api.example.com:443=1.1.1.1,127.0.0.1",
        "https://api.example.com:443=1.1.1.1,169.254.169.254",
        "https://api.example.com:443=1.1.1.1,::1",
        "https://api.example.com:443=1.1.1.1:8443",
        "https://api.example.com:443=1.1.1.1,1.1.1.1",
        "https://api.example.com:443=1.1.1.1,",
        "https://api.example.com:443=1.1.1.1;",
        "https://api.example.com:443=1.1.1.1;https://api.example.com:443=8.8.8.8",
        "http://api.example.com:80=1.1.1.1",
        "https://1.1.1.1:443=8.8.8.8",
        "https://api.example.com:443=1.1.1.1,1.1.1.2,1.1.1.3,1.1.1.4,1.1.1.5",
    ] {
        assert!(PublicTargets::parse(invalid).is_err(), "{invalid}");
    }
    assert!(PublicTargets::parse(&"x".repeat(2049)).is_err());
    let many = (0..17)
        .map(|i| format!("https://h{i}.test:443=1.1.1.1"))
        .collect::<Vec<_>>()
        .join(";");
    assert!(PublicTargets::parse(&many).is_err());
    let many_addresses = (0..9)
        .map(|i| format!("https://h{i}.test:443=1.1.1.1,1.1.1.2,1.1.1.3,1.1.1.4"))
        .collect::<Vec<_>>()
        .join(";");
    assert!(PublicTargets::parse(&many_addresses).is_err());
}
