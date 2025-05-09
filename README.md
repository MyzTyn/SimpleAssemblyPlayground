# SimpleAssemblyPlayground

A fun little playground to write and run x86 Assembly code (currently using AT&T syntax).  
This project is cross-platform (Windows, Linux & MacOS).

Feel free to contribute to the project!

---

## ✨ Features

- IA-32 (x86) assembly execution
- Memory Editor
- AT&T syntax parsing
- Basic Breakpoint

---

## 🛠️ Build Instructions

### Prerequisites

- CMake
- Python (For Keystone library), pkg-config
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

## How to Use

Before you begin, make sure to compile the assembly code so it can be executed or debugged.

### Console Window
- To clear the logs, either enter the `CLEAR` command or right-click in the console window and select **Clear**.

### Disassembly Window
- To scroll through instructions, make sure **AutoScroll** is disabled.
- Toggle breakpoints by either:
  - Double-clicking an instruction
  - Right-clicking and selecting **Toggle Breakpoint**

