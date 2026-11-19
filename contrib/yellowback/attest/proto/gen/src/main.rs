// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Generates the lightwalletd client stubs the light backend uses (`../../src/light/proto.rs`) from the pinned
//! protos beside this directory. Run through `../regen.sh`, which needs `protoc`; the agent's own build never does.
//! Every message also derives `serde::Serialize` with camelCase names: the protos' field names are the node's JSON
//! names, so a message serializes to the shape the node's RPC returns.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (proto_dir, out_dir) = (&args[1], &args[2]);
    let protos: Vec<String> = ["service.proto", "compact_formats.proto", "yellowback.proto"]
        .iter()
        .map(|p| format!("{proto_dir}/{p}"))
        .collect();
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .build_transport(true)
        .out_dir(out_dir)
        .type_attribute(".", "#[derive(serde::Serialize)]")
        .type_attribute(".", "#[serde(rename_all = \"camelCase\")]")
        .compile_protos(&protos, &[proto_dir.clone()])
        .expect("protoc failed: install protobuf (brew install protobuf / apt install protobuf-compiler)");
}
