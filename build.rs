fn main() {
    protobuf_codegen::Codegen::new()
        .cargo_out_dir("protos")
        .include("src")
        .input("src/protos/initialize.proto")
        .input("src/protos/recover.proto")
        .run_from_script();
}