cmake_minimum_required(VERSION 3.11)
project(IA32_Emulator)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Library Config #
set(UNICORN_ARCH "X86") # UNICORN ONLY X86
set(LLVM_TARGETS_TO_BUILD "X86") # Keystone
set(CAPSTONE_X86_SUPPORT ON)

# Add Unicorn Engine as a library
add_subdirectory(${CMAKE_SOURCE_DIR}/vendor/unicorn)
# Add Keystone as a library
add_subdirectory(${CMAKE_SOURCE_DIR}/vendor/keystone)
# Add Capstone as a library
add_subdirectory(${CMAKE_SOURCE_DIR}/vendor/capstone)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/vendor/unicorn/include)
include_directories(${CMAKE_SOURCE_DIR}/vendor/keystone/include)
include_directories(${CMAKE_SOURCE_DIR}/vendor/capstone/include)
include_directories(${CMAKE_SOURCE_DIR}/src/AssemblyPlayground)  # Include your source folder

include_directories(${CMAKE_SOURCE_DIR}/vendor/imgui/ ${CMAKE_SOURCE_DIR}/vendor/imgui/backends)
# Add ImGui source files
set(IMGUI_SRC
    ${CMAKE_SOURCE_DIR}/vendor/imgui/imgui.cpp
    ${CMAKE_SOURCE_DIR}/vendor/imgui/imgui_draw.cpp
    ${CMAKE_SOURCE_DIR}/vendor/imgui/imgui_tables.cpp
    ${CMAKE_SOURCE_DIR}/vendor/imgui/imgui_widgets.cpp
    ${CMAKE_SOURCE_DIR}/vendor/imgui/imgui_demo.cpp
)
# Detect platform and add the correct backend
if (APPLE)
    list(APPEND IMGUI_SRC
        ${CMAKE_SOURCE_DIR}/vendor/imgui/backends/imgui_impl_metal.mm
        ${CMAKE_SOURCE_DIR}/vendor/imgui/backends/imgui_impl_osx.mm
    )
elseif (WIN32)
    list(APPEND IMGUI_SRC
        ${CMAKE_SOURCE_DIR}/vendor/imgui/backends/imgui_impl_dx12.cpp
        ${CMAKE_SOURCE_DIR}/vendor/imgui/backends/imgui_impl_win32.cpp
    )
endif()

# Find all .cpp and .h
file(GLOB_RECURSE SOURCE_FILES CONFIGURE_DEPENDS
    ${CMAKE_SOURCE_DIR}/src/AssemblyPlayground/*.cpp
    ${CMAKE_SOURCE_DIR}/src/AssemblyPlayground/*.h
)

# Main entrypoint
if (APPLE)
    list(APPEND SOURCE_FILES
        ${CMAKE_SOURCE_DIR}/src/Platform/MacOSX/main_osx.mm
    )
elseif (WIN32)
    list(APPEND SOURCE_FILES
        ${CMAKE_SOURCE_DIR}/src/Platform/Windows/main_win32_dx12.cpp
    )
endif()

# Create the executable
add_executable(ia32_emulator ${SOURCE_FILES} ${IMGUI_SRC})

# macOS: Link Metal framework (move it here after `add_executable`)
if (APPLE)
    target_link_libraries(ia32_emulator "-framework Metal" "-framework MetalKit" "-framework Cocoa" "-framework GameController" "-framework QuartzCore" "-framework AppKit")
    # Mark several errors as warning to get it work
    target_compile_options(capstone PRIVATE -Wno-conversion -Wno-sign-compare -Wno-ignored-qualifiers -Wno-unused-parameter -Wno-missing-field-initializers)
elseif (WIN32)
    target_link_libraries(ia32_emulator d3d12.lib dxgi.lib d3dcompiler.lib dxguid.lib)
endif()

# Link against libs statically
target_link_libraries(ia32_emulator unicorn keystone capstone)

