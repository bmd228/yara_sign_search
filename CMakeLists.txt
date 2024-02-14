# CMakeList.txt: проект CMake для CMakeProject1; включите исходный код и определения,
# укажите здесь логику для конкретного проекта.
#
cmake_minimum_required (VERSION 3.8)

project ("CMakeProject1")
#find_library(GMIME_LIB gmime-3.0 REQUIRED)
#find_path(GMIME_LIB_INCLUDE gmime)

find_library(Y_LIB libyara REQUIRED)
find_path(Y_LIB_INCLUDE yara)
find_package(OpenSSL REQUIRED)
find_package(jansson CONFIG REQUIRED)
# Добавьте источник в исполняемый файл этого проекта.
find_package(re2 CONFIG REQUIRED)
find_package(Qt5 COMPONENTS Core Xml REQUIRED)
add_executable (${PROJECT_NAME}  "CMakeProject1.cpp" "CMakeProject1.h"  "json.hpp")
#target_include_directories(CMakeProject1 PRIVATE ${GMIME_LIB_INCLUDE})
#target_link_libraries(CMakeProject1 PRIVATE ${GMIME_LIB})
target_include_directories(CMakeProject1 PRIVATE ${Y_LIB_INCLUDE})
target_link_libraries(CMakeProject1 PRIVATE jansson::jansson)
target_link_libraries(CMakeProject1 PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(CMakeProject1 PRIVATE ${Y_LIB})
target_link_libraries(${PROJECT_NAME} PRIVATE Qt5::Core Qt5::Xml)
target_link_libraries(${PROJECT_NAME} PRIVATE re2::re2)
target_compile_features(${PROJECT_NAME}  PRIVATE cxx_std_17)
# TODO: Добавьте тесты и целевые объекты, если это необходимо.
