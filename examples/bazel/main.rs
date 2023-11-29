//! Example of a Rust binary that makes use of Sandwich.
extern crate protobuf;
extern crate sandwich;

use sandwich::pb_api as sw_api;
use sandwich::tunnel;

/// Protobuf configuration for a TLS client.
const TLS_CLIENT_PROTO_CONF: &str = r#"
client <
    tls <
        common_options <
            kem: "X25519"
            kem: "prime256v1"
            kem: "kyber768"
            x509_verifier <
                trusted_cas <
                    static <
                        data <
                            filename: "/etc/ssl/cert.pem"
                        >
                        format: ENCODING_FORMAT_PEM
                    >
                >
            >
            alpn_protocol: "h2"
            alpn_protocol: "http/1.1"
        >
    >
>"#;

/// Creates a Sandwich context ([`sandwich::tunnel::Context`]).
fn create_context(sw: &sandwich::Context) -> tunnel::Context {
    let configuration =
        protobuf::text_format::parse_from_str::<sw_api::Configuration>(TLS_CLIENT_PROTO_CONF)
            .expect("cannot create a configuration");
    tunnel::Context::try_from(sw, &configuration).expect("cannot create a Sandwich context")
}

fn main() {
    let sw = sandwich::Context::new();
    let _context = create_context(&sw);
    // See `/examples/rust` for a more complete example.
}
