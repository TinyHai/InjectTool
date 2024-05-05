fn main() {
    cc::Build::new().file("cpp/fake_dlfcn.cpp").compile("fake_dlfcn");
}