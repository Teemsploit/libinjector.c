# libinjector.c

A simple Linux library for injecting shared objects (.so) into other processes using ptrace and dlopen.

## Build

```bash
make
```

## Example Usage

```bash
./injector firefox ./examples/example_inject.so
```

Make sure `test_inject.so` exists and the target process is running.
