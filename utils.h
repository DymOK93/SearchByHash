#pragma once
#include <type_traits>

template <class Ty>
constexpr auto* pointer_cast(void* ptr) noexcept {
  return static_cast<Ty*>(ptr);
}

template <class Ty>
constexpr auto* pointer_cast(const void* ptr) noexcept {
  return static_cast<const Ty*>(ptr);
}

template <class Ty>
constexpr bool bool_cast(Ty&& val) noexcept(
    noexcept(static_cast<bool>(std::forward<Ty>(val)))) {
  return static_cast<bool>(std::forward<Ty>(val));
}