cmake_minimum_required(VERSION 3.16)
project(gapcoin_blockchain_reader LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Qt6 COMPONENTS Widgets Network QUIET)
if(Qt6_FOUND)
  set(QT_PACKAGE Qt6)
else()
  find_package(Qt5 REQUIRED COMPONENTS Widgets Network)
  set(QT_PACKAGE Qt5)
endif()

set(SOURCES
  src/main.cpp
  src/MainWindow.cpp
  src/RpcClient.cpp
)

set(HEADERS
  src/MainWindow.h
  src/RpcClient.h
)

add_executable(gapcoin-blockchain-reader
  ${SOURCES}
  ${HEADERS}
)

target_link_libraries(gapcoin-blockchain-reader
  PRIVATE
    ${QT_PACKAGE}::Widgets
    ${QT_PACKAGE}::Network
)

if(MSVC)
  target_compile_definitions(gapcoin-blockchain-reader PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
