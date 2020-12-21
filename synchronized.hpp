#pragma once

#include <mutex>
#include <shared_mutex>
#include <type_traits>

template <class Ty>
class Synchronized {
 public:
  using value_type = std::remove_const_t<std::remove_reference_t<Ty>>;
  using mutex_t = std::mutex;
  using guard_t = std::lock_guard<mutex_t>;


  template <class Guard, class Value>
  struct Reference {
    template <class Mutex>
    Reference(Mutex& mtx, Value& value) : guard(mtx), ref_to_value(value) {}

    Guard guard;
    Value& ref_to_value;
  };

  using reference = Reference<guard_t, value_type>;
  using const_reference = Reference<guard_t, const value_type>;

 public:
  template <class U = Ty,
            std::enable_if_t<std::is_default_constructible_v<U>, int> = 0>
  Synchronized() noexcept(std::is_nothrow_default_constructible_v<Ty>) {}

  Synchronized(const Synchronized&) = default;
  Synchronized(Synchronized&&) = default;

    template <class... Types>
  Synchronized(std::in_place_t, Types&&... args) noexcept(
      std::is_nothrow_constructible_v<Ty, Types...>)
      : m_value(std::forward<Types>(args)...) {}

  Synchronized& operator=(const Synchronized&) = default;
  Synchronized& operator=(Synchronized&&) = default;

  Synchronized& operator=(const Ty& new_value) {
    GetAccess().ref_to_value = new_value;
    return *this;
  }

   Synchronized& operator=(Ty&& new_value) {
    GetAccess().ref_to_value = std::move(new_value);
    return *this;
  }

  reference GetAccess() { return reference(m_mtx, m_value); }

  const_reference GetAccess() const { return const_reference(m_mtx, m_value); }

 private:
  Ty m_value{};
  mutable mutex_t m_mtx;
};