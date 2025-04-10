cmake_minimum_required(VERSION 3.11)
project(SimpleAssemblyPlayground)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Library Config #
set(UNICORN_ARCH "x86")                 # UNICORN ONLY X86

set(LLVM_TARGETS_TO_BUILD "X86")        # Keystone
set(BUILD_LIBS_ONLY ON)                 # Keystone
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF)  # Capstone
set(CAPSTONE_X86_SUPPORT ON)            # Capstone

# GLFW
set(GLFW_BUILD_EXAMPLES OFF)
set(GLFW_BUILD_TESTS OFF)
set(GLFW_BUILD_DOCS OFF)
set(GLFW_INSTALL OFF)

# Add Unicorn Engine as a library
add_subdirectory(${CMAKE_SOURCE_DIR}/vendor/unicorn)
# Add Keystone as a library
add_subdirectory(${CMAKE_SOURCE_DIR}/vendor/keystone)
# Add Capstone as a library
add_subdirectory(${CMAKE_SOURCE_DIR}/vendor/capstone)

if (UNIX AND NOT APPLE)
    find_package(Vulkan REQUIRED)
    add_subdirectory(${CMAKE_SOURCE_DIR}/vendor/glfw)
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/vendor/unicorn/include)
include_directories(${CMAKE_SOURCE_DIR}/vendor/keystone/include)
include_directories(${CMAKE_SOURCE_DIR}/vendor/capstone/include)
include_directories(${CMAKE_SOURCE_DIR}/vendor/glfw/include)
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
elseif (UNIX AND NOT APPLE)
    list(APPEND IMGUI_SRC
        ${CMAKE_SOURCE_DIR}/vendor/imgui/backends/imgui_impl_vulkan.cpp
        ${CMAKE_SOURCE_DIR}/vendor/imgui/backends/imgui_impl_glfw.cpp
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
elseif (UNIX)
    list(APPEND SOURCE_FILES
        ${CMAKE_SOURCE_DIR}/src/Platform/Linux/main_glfw_vulkan.cpp
    )
endif()

# Create the executable
add_executable(SimpleAssemblyPlayground ${SOURCE_FILES} ${IMGUI_SRC})

# macOS: Link frameworks
if (APPLE)
    target_link_libraries(SimpleAssemblyPlayground "-framework Metal" "-framework MetalKit" "-framework Cocoa" "-framework GameController" "-framework QuartzCore" "-framework AppKit")
    # Mark several errors as warning to get it work
    target_compile_options(capstone PRIVATE -Wno-conversion -Wno-sign-compare -Wno-ignored-qualifiers -Wno-unused-parameter -Wno-missing-field-initializers)
elseif (WIN32)
    target_link_libraries(SimpleAssemblyPlayground d3d12.lib dxgi.lib d3dcompiler.lib dxguid.lib)
elseif (UNIX)
    target_link_libraries(SimpleAssemblyPlayground glfw Vulkan::Vulkan)
    target_compile_definitions(SimpleAssemblyPlayground PRIVATE
    GLFW_INCLUDE_NONE
    GLFW_INCLUDE_VULKAN
)
endif()

# Link against libs statically
target_link_libraries(SimpleAssemblyPlayground unicorn keystone capstone)

