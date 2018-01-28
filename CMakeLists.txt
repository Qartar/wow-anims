cmake_minimum_required(VERSION 3.0)

project(wow-anims)

add_executable(wow-anims wow-anims.cpp)
target_link_libraries(wow-anims Mincore)
