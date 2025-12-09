#pragma once

#include "td/utils/StringBuilder.h"

namespace cocoon {

struct SimpleJsonSerializer {
  td::StringBuilder sb;
  td::int32 offset = 0;
  std::vector<bool> stack{false};
  void print_offset() {
    for (td::int32 i = 0; i < offset; i++) {
      sb << ' ';
    }
  }
  void print_comma() {
    if (stack.back()) {
      sb << ",\n";
    } else {
      sb << "\n";
    }
    stack.back() = true;
    print_offset();
  }
  void start_object() {
    print_comma();
    sb << "{";
    offset += 2;
    stack.push_back(false);
  }
  void start_array() {
    print_comma();
    sb << "[";
    offset += 2;
    stack.push_back(false);
  }
  void start_object(td::Slice name) {
    print_comma();
    sb << "\"" << name << "\": {";
    offset += 2;
    stack.push_back(false);
  }
  void start_array(td::Slice name) {
    print_comma();
    sb << "\"" << name << "\": [";
    offset += 2;
    stack.push_back(false);
  }
  void stop_object() {
    offset -= 2;
    sb << "\n";
    print_offset();
    sb << "}";
    stack.pop_back();
  }
  void stop_array() {
    offset -= 2;
    sb << "\n";
    print_offset();
    sb << "]";
    stack.pop_back();
  }

  void add_value(bool value) {
    sb << (value ? "true" : "false");
  }
  void add_value(td::int32 value) {
    sb << value;
  }
  void add_value(td::uint32 value) {
    sb << value;
  }
  void add_value(td::int64 value) {
    sb << value;
  }
  void add_value(td::uint64 value) {
    sb << value;
  }
  void add_value(double value) {
    sb << value;
  }
  template <typename T>
    requires std::is_arithmetic_v<T>
  void add_value(T value) {
    sb << value;
  }
  void add_value(td::Slice value) {
    sb << "\"" << value << "\"";
  }
  void add_value(const char *value) {
    sb << "\"" << td::CSlice(value) << "\"";
  }
  template <size_t N>
  void add_value(const char value[N]) {
    sb << "\"" << td::Slice(value, N) << "\"";
  }

  void add_element(td::Slice name, auto value) {
    print_comma();
    add_value(name);
    sb << ": ";
    add_value(value);
  }

  void add_element(auto value) {
    print_comma();
    add_value(value);
  }

  td::CSlice as_cslice() {
    return sb.as_cslice();
  }
};

}  // namespace cocoon
