cargo add axum --features "macros,multipart"
cargo add tokio --features "full"
cargo add tower --features "util"
cargo add tower-http --features "fs,trace,cors,compression-gzip"
cargo add sqlx --features "runtime-tokio-rustls,postgres,uuid,chrono,json,migrate,macros"
cargo add serde --features "derive"
cargo add serde_json
cargo add chrono --features "serde"
cargo add uuid --features "v4,serde"
cargo add jsonwebtoken
cargo add argon2
cargo add rand
cargo add sha2
cargo add hex
cargo add reqwest --features "json,rustls-tls"
cargo add futures
cargo add futures-util
cargo add dotenvy
cargo add tracing
cargo add tracing-subscriber --features "env-filter"
cargo add anyhow
cargo add thiserror
cargo add validator --features "derive"
cargo add lettre --features "tokio1-rustls-tls"
cargo add mime
cargo add mime_guess
cargo add governor
cargo add rsa --features "sha2"
cargo add base64
cargo add url
cargo add regex
cargo add --dev tokio-test
cargo add --dev tempfile