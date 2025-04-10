# SimpleAssemblyPlayground

A fun little playground to write and run x86 Assembly code (currently using AT&T syntax).  
This project is cross-platform (Windows, Linux & MacOS).

---

## ✨ Features

- IA-32 (x86) assembly execution
- Memory Editor
- AT&T syntax parsing
- Playground-style interface

---

## 🛠️ Build Instructions

### Prerequisites

- CMake
- A C++14-compatible compiler
- macOS, Linux, or Windows (cross-platform support)

> *Note for Linux users*
> You may need to install dependencies for glfw (https://www.glfw.org/docs/latest/compile.html)

### Steps

1. **Clone the repository** and initialize submodules:
```bash
git submodule update --init --recursive
```

2. Create a build directory and generate the build system (example: Xcode on macOS):
```bash
mkdir build && cd build
cmake .. -G Xcode
```
> For other platforms or IDEs, adjust the -G argument accordingly:
> - macOS (Makefiles): -G "Unix Makefiles"
> - Windows (Visual Studio): -G "Visual Studio 17 2022"

3. Build and run the project
   Open the generated project in your IDE and build the SimpleAssemblyPlayground target.

> *Note for Windows users:*
> You may encounter an "Access Violation" error when executing Unicorn on Windows.
> This is a known issue with Unicorn (see unicorn-engine/unicorn#1841).
> It is generally safe to ignore for development and debugging purposes.
