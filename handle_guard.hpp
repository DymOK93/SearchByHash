#pragma once
#include "winapi_typedefs.h"

#include <memory>
#include <functional>
#include <type_traits>

namespace winapi {
using handle_guard_t = std::unique_ptr<std::remove_pointer_t<handle_t>,
                                       std::function<void(handle_t)>>;

template <class Guard>
handle_guard_t MakeHandleGuard(handle_t handle, Guard&& guard) {
  return std::unique_ptr<std::remove_pointer_t<handle_t>,
                         std::function<void(handle_t)>>(
      handle, std::function<void(HANDLE)>(std::forward<Guard>(guard)));
}

inline handle_guard_t MakeHandleGuard(handle_t handle) {
  auto guard{[](handle_t target) { CloseHandle(target); }}; // unique_ptr сам проверяет на nullptr
  return MakeHandleGuard(handle, std::move(guard));
}

namespace details {
template <class Opener, class... Types>
handle_t OpenRawHandle(Opener&& opener, Types&&... args) {
  return std::invoke(std::forward<Opener>(opener),
                     std::forward<Types>(args)...);
}
}  // namespace details

template <class Opener, class... Types>
handle_guard_t OpenHandle(Opener&& opener, Types&&... args) {
  return MakeHandleGuard(OpenRawHandle(std::forward<Opener>(opener),
                                       std::forward<Types>(args)...));
}

template <class Opener, class Guard, class... Types>
handle_guard_t OpenHandle(Opener&& opener, Guard&& guard, Types&&... args) {
  return MakeHandleGuard(details::OpenRawHandle(std::forward<Opener>(opener),
                                                std::forward<Types>(args)...),
                         std::forward<Guard>(guard));
}

}  // namespace winapi
