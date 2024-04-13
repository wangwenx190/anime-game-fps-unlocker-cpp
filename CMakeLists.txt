cmake_minimum_required(VERSION 3.28)

project(GI-FPS-Unlocker VERSION "1.1.0" LANGUAGES CXX RC)

if(NOT DEFINED CMAKE_BUILD_TYPE AND NOT DEFINED CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

if(NOT DEFINED CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
endif()

if(MSVC)
    set(CMAKE_RC_FLAGS "-c65001 -DWIN32 -nologo")
endif()

find_package(qmsetup QUIET)
if(NOT TARGET qmsetup::library)
    set(_qms_source_dir "${CMAKE_CURRENT_SOURCE_DIR}/qmsetup")
    include("${_qms_source_dir}/cmake/modules/InstallPackage.cmake")
    set(_qms_package_path)
    qm_install_package(qmsetup
        SOURCE_DIR ${_qms_source_dir}
        BUILD_TYPE Release
        RESULT_PATH _qms_package_path
    )
    find_package(qmsetup REQUIRED PATHS ${_qms_package_path})
    set(qmsetup_DIR ${_qms_package_path} CACHE PATH "" FORCE)
endif()

if(MSVC)
    # Make sure we always overwrite the previous settings if any.
    unset(CMAKE_MSVC_RUNTIME_LIBRARY)
    unset(CMAKE_MSVC_RUNTIME_LIBRARY CACHE)
    #unset(CMAKE_MSVC_RUNTIME_LIBRARY PARENT_SCOPE)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>" CACHE STRING "" FORCE)
    include("./qmsetup/cmake/find-modules/VC-LTL.cmake")
    unset(YYTHUNKS_TARGET_OS)
    unset(YYTHUNKS_TARGET_OS CACHE)
    #unset(YYTHUNKS_TARGET_OS PARENT_SCOPE)
    set(YYTHUNKS_TARGET_OS "WinXP" CACHE STRING "" FORCE)
    include("./qmsetup/cmake/find-modules/YY-Thunks.cmake")
endif()

qm_import(Filesystem CompilerOptions)
qm_init_directories()
qm_compiler_no_warnings()
qm_compiler_dont_export_by_default()
if(NOT "x${CMAKE_BUILD_TYPE}" STREQUAL "xDebug")
    qm_compiler_eliminate_dead_code()
endif()

add_executable(${PROJECT_NAME} main.cpp)

set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION "${PROJECT_VERSION}"
)

target_compile_definitions(${PROJECT_NAME} PRIVATE
    WIN32_LEAN_AND_MEAN WINRT_LEAN_AND_MEAN
    UNICODE _UNICODE
    _USE_MATH_DEFINES
    NOMINMAX
)

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /options:strict /FS /MP /utf-8 /Zc:__cplusplus /permissive-
        /guard:cf /guard:ehcont /Qspectre-jmp /Qspectre-load-cf
        $<$<NOT:$<CONFIG:Debug>>:/Gw /Gy /Zc:inline>
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        /DYNAMICBASE /FIXED:NO /NXCOMPAT /HIGHENTROPYVA /TSAWARE
        /LARGEADDRESSAWARE /CETCOMPAT /GUARD:CF /guard:ehcont /WX
        $<$<NOT:$<CONFIG:Debug>>:/OPT:REF /OPT:ICF /OPT:LBR>
    )
endif()

set(_desc "FPS unlocker for a certain anime game")
qm_add_win_rc_enhanced(${PROJECT_NAME}
    NAME "Genshin Impact FPS Unlocker"
    VERSION "${PROJECT_VERSION}"
    DESCRIPTION "${_desc}"
    COPYRIGHT "MIT License"
    COMPANY "wangwenx190"
    COMMENTS "XX, start!"
    ICONS "${CMAKE_CURRENT_SOURCE_DIR}/icon/app.ico"
)
qm_add_win_manifest(${PROJECT_NAME} UTF8
    NAME "org.wangwenx190.GenshinImpactFPSUnlocker"
    DESCRIPTION "${_desc}"
)

include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME}
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)
