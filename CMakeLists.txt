cmake_minimum_required(VERSION 3.14)

project(TinyPG LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Network)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Network)

add_executable(TinyPGExample TinyPG.cpp TinyPG.h example.cpp)
target_link_libraries(TinyPGExample Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::Network)
add_library(TinyPG_Shared SHARED TinyPG.cpp TinyPG.h)
target_compile_definitions(TinyPG_Shared PRIVATE SHARED_LIB=1)
set_target_properties(TinyPG_Shared PROPERTIES OUTPUT_NAME "TinyPG")
target_link_libraries(TinyPG_Shared Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::Network)
add_library(TinyPG_static STATIC TinyPG.cpp TinyPG.h)
target_link_libraries(TinyPG_static Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::Network)

include(GNUInstallDirs)
install(TARGETS TinyPGExample TinyPG_Shared TinyPG_static
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
