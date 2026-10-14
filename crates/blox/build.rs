use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=protos");

    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    let proto_root = PathBuf::from("protos");
    let service_proto = proto_root.join("xyz/block/blox/orchestrator/v1/orchestrator.proto");
    let descriptor_path = PathBuf::from(std::env::var("OUT_DIR")?).join("proto_descriptor.bin");

    tonic_prost_build::configure()
        .build_client(false)
        .build_server(false)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&[service_proto], &[proto_root])?;

    let descriptor_set = std::fs::read(descriptor_path)?;
    pbjson_build::Builder::new()
        .register_descriptors(&descriptor_set)?
        .ignore_unknown_fields()
        .ignore_unknown_enum_variants()
        .build(&[".xyz.block.blox.orchestrator.v1"])?;
    Ok(())
}
