extern crate cc;

fn main() {
    cc::Build::new()
        .file("ctrans/transpose.c")
        .flag("-maes")
        .flag("-msse4.1")
        .compile("libtranspose.a");
}
