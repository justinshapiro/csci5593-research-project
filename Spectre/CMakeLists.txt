cmake_minimum_required(VERSION 3.9)
project(csci5593-research-project/Spectre)

set(CMAKE_C_STANDARD 11)

set(SOURCE_FILES Spectre.c FlushReload.c CacheTime.c Spectre_hydra.c)

add_executable(Spectre Spectre.c)

add_executable(FlushReload FlushReload.c)

add_executable(CacheTime CacheTime.c)

add_executable(Spectre_hydra Spectre_hydra.c)