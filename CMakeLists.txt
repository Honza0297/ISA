cmake_minimum_required(VERSION 3.15)
project(ISA C)

set(CMAKE_C_STANDARD 99)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lpcap")
add_executable(ISA
      main.c)

