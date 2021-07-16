use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process;
use walkdir::WalkDir;

macro_rules! info {
    ($msg:expr) => {
         println!("[info] {}", $msg)
    };
    ($fmt:expr, $($arg:tt)+) => {
        info!(&format!($fmt, $($arg)+))
    };
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let project_dir = root.parent().unwrap().parent().unwrap().parent().unwrap();
    println!("{:?}", project_dir);
    let proto_paths = [
        PathBuf::from(format!("{}/proto/gravity/v1", project_dir.display())),
        PathBuf::from(format!("{}/proto/other", project_dir.display())),
    ];

    let gopath = std::env::var("GOPATH");
    let sdk_dir = match gopath {
        Ok(v) => PathBuf::from(v).join(PathBuf::from("src/github.com/cosmos/cosmos-sdk")),
        Err(_) => {
            let temp_dir = std::env::temp_dir();
            let sdk_dir = temp_dir.join(PathBuf::from("cosmos-sdk"));
            info!("git temp dir by cosmos sdk '{}'", sdk_dir.display());
            run_git(&["clone", "--depth", "1", "https://github.com/cosmos/cosmos-sdk.git", format!("{}", sdk_dir.display()).as_str()]);
            sdk_dir
        }
    };
    let proto_include_paths = [
        PathBuf::from(format!("{}/proto", project_dir.display())),
        PathBuf::from(format!("{}/proto", sdk_dir.display())),
        PathBuf::from(format!("{}/third_party/proto", sdk_dir.display())),
    ];

    let out_path = PathBuf::from(format!("{}/fxchain/src/prost/", root.parent().unwrap().display()));

    compile_protos(&proto_paths, &proto_include_paths, &out_path);

    let exclude_files = &[PathBuf::from("fx.gravity.v1.rs")];
    remove_file_exclude(&out_path, exclude_files);
}

// proto_include_dir:
// we need to have an include which is just the folder of our protos to satisfy protoc
// which insists that any passed file be included in a directory passed as an include
fn compile_protos(proto_paths: &[PathBuf], proto_include_paths: &[PathBuf], out_dir: &Path) {
    info!("Compiling .proto files to Rust into '{}'...", out_dir.display());

    // List available proto files
    let mut protos: Vec<PathBuf> = vec![];
    for proto_path in proto_paths {
        protos.append(
            &mut WalkDir::new(proto_path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file() && e.path().extension().is_some() && e.path().extension().unwrap() == "proto")
                .map(|e| e.into_path())
                .collect(),
        );
    }

    // Compile all proto files
    let mut config = prost_build::Config::default();
    config.out_dir(out_dir);
    config.compile_well_known_types().compile_protos(&protos, &proto_include_paths).unwrap();

    info!("Compiling proto clients for GRPC services!");
    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .format(false)
        .out_dir(out_dir)
        .compile(&protos, &proto_include_paths)
        .unwrap();

    info!("=> Compiling Done!");
}

fn remove_file_exclude(work_dir: &Path, exclude_files: &[PathBuf]) {
    let read_dir = std::fs::read_dir(work_dir).unwrap();
    for entry in read_dir {
        let path_name = entry.unwrap().path();
        if path_name.is_dir() {
            continue;
        }
        let mut is_exclude = false;
        for file_name in exclude_files {
            if path_name.file_name().unwrap().eq(file_name) {
                is_exclude = true;
            }
        }
        if is_exclude {
            continue;
        }
        info!("Remove unwanted files with '{}'", path_name.display());
        std::fs::remove_file(path_name.clone()).expect(format!("{}", path_name.display()).as_str())
    }
}

fn run_git(args: impl IntoIterator<Item = impl AsRef<OsStr>>) {
    let stdout = process::Stdio::inherit();
    let exit_status = process::Command::new("git").args(args).stdout(stdout).status().expect("git exit status missing");

    if !exit_status.success() {
        panic!("git exited with error code: {:?}", exit_status.code());
    }
}
