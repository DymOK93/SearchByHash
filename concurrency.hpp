#pragma once
#include <atomic>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>

namespace details {
template <class Tuple>
auto make_index_sequence_for_tuple() {
  return std::make_index_sequence<std::tuple_size_v<Tuple>>{};
}

template <class Function, class ArgTuple, size_t... Indices>
struct invoke_result_impl {
  using type = std::invoke_result_t<Function,
                                    decltype(std::move(std::get<Indices>(
                                        std::declval<ArgTuple>())))...>;
};

template <class Function, class ArgTuple, size_t... Indices>
using invoke_result_impl_t =
    typename invoke_result_impl<Function, ArgTuple, Indices...>::type;

template <class Function, class ArgTuple, size_t... Indices>
invoke_result_impl_t<Function, ArgTuple, Indices...> get_invoke_result(
    std::index_sequence<Indices...>);

template <class Function, class ArgTuple>
struct invoke_result {
  using type = decltype(get_invoke_result<Function, ArgTuple>(
      make_index_sequence_for_tuple<ArgTuple>()));
};

template <class Function, class ArgTuple>
using invoke_result_t = typename invoke_result<Function, ArgTuple>::type;

template <class... Types>
struct argument_tuple {
  using type = typename std::tuple<std::decay_t<Types>...>;
};

template <class... Types>
using argument_tuple_t = typename argument_tuple<Types...>::type;

template <template <class, class> class Task, class Function, class... Types>
struct async_task {
  using type = Task<std::decay_t<Function>, argument_tuple_t<Types...>>;
};

template <template <class, class> class Task, class Function, class... Types>
using async_task_t = typename async_task<Task, Function, Types...>::type;
}  // namespace details

namespace async {
class ITask {
 public:
  using result_t = bool;

 public:
  virtual ~ITask() = default;
  virtual result_t Process() noexcept = 0;

 protected:
  static result_t operation_successful() noexcept { return true; }
  template <class Exception>
  static result_t exception_thrown(const Exception& exc) noexcept {
    (void)exc;
    return false;
  }
  static result_t unknown_exception_thrown() noexcept { return false; }
};

using task_holder = std::unique_ptr<ITask>;

template <class Function, class ArgTuple>
class DetachedTask : public ITask {
 public:
  using MyBase = ITask;
  using result_t = MyBase::result_t;

 public:
  template <class Func, class Tuple>
  DetachedTask(Func&& func, Tuple&& args)
      : m_func(std::forward<Func>(func)), m_args(std::forward<Tuple>(args)) {}

  result_t Process() noexcept override {
    try {
      call_with_unpacked_args(m_func, m_args);
    } catch (const std::exception& exc) {
      return exception_thrown(exc);
    } catch (...) {
      return unknown_exception_thrown();
    }
    return operation_successful();
  }

 protected:
  static decltype(auto) call_with_unpacked_args(Function& func,
                                                ArgTuple& args) {
    return call_with_unpacked_args_impl(
        func, args, details::make_index_sequence_for_tuple<ArgTuple>());
  }

  template <size_t... Indices>
  static decltype(auto) call_with_unpacked_args_impl(
      Function& func,
      ArgTuple& args,
      std::index_sequence<Indices...>) {
    return std::invoke(func, std::move(std::get<Indices>(args))...);
  }

 protected:
  Function m_func;
  ArgTuple m_args;
};

template <class Function, class ArgTuple>
class PackagedTask : public DetachedTask<Function, ArgTuple> {
 private:
  using MyBase = DetachedTask<Function, ArgTuple>;
  using result_t = typename MyBase::result_t;
  using ret_t = details::invoke_result_t<Function, ArgTuple>;
  using future_t = std::future<ret_t>;

 public:
  template <class Func, class Tuple>
  PackagedTask(Func&& func, Tuple&& args)
      : MyBase(std::forward<Func>(func), std::forward<Tuple>(args)) {}

  future_t GetFuture() { return m_promise.get_future(); }

  result_t Process() noexcept override {
    try {
      if constexpr (std::is_same_v<ret_t, void>) {
        MyBase::call_with_unpacked_args(MyBase::m_func, MyBase::m_args);
      } else {
        m_promise.set_value(
            MyBase::call_with_unpacked_args(MyBase::m_func, MyBase::m_args));
      }
    } catch (const std::exception& exc) {
      return MyBase::exception_thrown(exc);
    } catch (...) {
      try {
        m_promise.set_exception(
            std::current_exception());  //Может бросить std::future_error
      } catch (const std::future_error& exc) {
        return MyBase::exception_thrown(exc);
      }
      return MyBase::unknown_exception_thrown();
    }
    return MyBase::operation_successful();
  }

 protected:
  std::promise<ret_t> m_promise;
};

template <template <class, class> class Task, class Function, class... Types>
auto MakeTask(Function&& func, Types&&... args) {
  using task_t = details::async_task_t<Task, Function, Types...>;
  static_assert(std::is_base_of_v<ITask, task_t>,
                "Task must be derived from ITask");
  return task_t(
      std::forward<Function>(func),
      details::argument_tuple_t<Types...>{std::forward<Types>(args)...});
}

template <template <class, class> class Task, class Function, class... Types>
auto MakeTaskHolder(Function&& func, Types&&... args)
    -> std::unique_ptr<details::async_task_t<Task, Function, Types...>> {
  using task_t = details::async_task_t<Task, Function, Types...>;
  static_assert(std::is_base_of_v<ITask, task_t>,
                "Task must be derived from ITask");
  return std::make_unique<task_t>(
      std::forward<Function>(func),
      details::argument_tuple_t<Types...>{std::forward<Types>(args)...});
}
}  // namespace async

class ThreadController {
 public:
  ThreadController() = default;
  ThreadController(bool stopped_at_creation) : m_stop{stopped_at_creation} {}

  ~ThreadController() {
    if (!Stopped()) {
      Stop();
      NotifyAll();
    }
  }

  void Stop() noexcept { m_stop = true; }

  void Continue() noexcept { m_stop = false; }

  void Wait() {
    std::unique_lock thread_waid_lock(m_mtx);
    m_cv.wait(thread_waid_lock);
  }

  template <class Predicate>
  void Wait(Predicate pred) {
    std::unique_lock thread_waid_lock(m_mtx);
    m_cv.wait(thread_waid_lock, pred);
  }

  void NotifyOne() { m_cv.notify_one(); }

  void NotifyAll() { m_cv.notify_all(); }

  bool InProgress() const noexcept { return !Stopped(); }

  bool Stopped() const noexcept { return m_stop; }

 private:
  std::atomic_bool m_stop{false};
  std::mutex m_mtx;
  std::condition_variable m_cv;
};
