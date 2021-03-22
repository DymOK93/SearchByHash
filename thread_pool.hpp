#pragma once
#include "concurrency.hpp"

#include <boost/lockfree/queue.hpp>

#include <vector>

template <class ConcretePool>
class ThreadPoolBase {
 protected:
  using lockfree_queue = boost::lockfree::queue<async::ITask*>;

 protected:
  static constexpr size_t QUEUE_CAPACITY_FACTOR{2};

 public:
  ~ThreadPoolBase() {
    m_controller.Stop();
    m_controller.NotifyAll();
    for (auto& worker : m_workers) {
      worker.join();
    }
  }

  template <class Function, class... Types>
  auto Schedule(Function&& func, Types&&... args) {
    static_assert(std::is_invocable_v<Function, Types...>,
                  "Impossible to invoke a callable with passed arguments");
    auto task_guard{
        async::MakeTaskHolder<async::PackagedTask, Function, Types...>(
            std::forward<Function>(func), std::forward<Types>(args)...)};
    /**********************************************************************************************************
    Объект future необходимо получить до отправки задачи в очередь - в противном
    случае есть вероятность возникновения гонки данных: <Поток 1>: <Задача
    создана> -> <Задача загружена в очередь> -> [timestamp] -> <future получен>
    -> <Возврат из функции> <Поток 2>: <Ожидание> -> <Задача выполняется> ->
    <Задача выполнена> -> <Объект Task удалён> -> [timestamp] При выбросе
    исключения не произойдет блокировки потока с future, ссылающимся на
    shared_state: см. https://en.cppreference.com/w/cpp/thread/future/%7Efuture:
    ...these actions will not block for the shared state to become ready,
    except that it may block if all of the following are true:
    > the shared state was created by a call to std::async
    > the shared state is not yet ready
    > [future object] was the last reference to the shared state
    **********************************************************************************************************/
    auto future{task_guard.get()->GetFuture()};
    if (!m_tasks.push(task_guard.get())) {
      throw std::runtime_error("Can't push task into queue");
    }
    m_controller.NotifyOne();
    task_guard.release();
    return future;
  }

  template <class Function, class... Types>
  void Enqueue(Function&& func, Types&&... args) {
    static_assert(std::is_invocable_v<Function, Types...>,
                  "Impossible to invoke a callable with passed arguments");
    auto task_guard{
        async::MakeTaskHolder<async::DetachedTask, Function, Types...>(
            std::forward<Function>(func), std::forward<Types>(args)...)};
    if (!m_tasks.push(task_guard.get())) {
      throw std::runtime_error("Can't push task into queue");
    }
    m_controller.NotifyOne();
    task_guard.release();
  }

  template <class Function, class... Types>
  void EnqueueMulti(const Function& func,
                    size_t task_count,
                    const Types&... args) {
    for (size_t task_idx = 0; task_idx < task_count; ++task_idx) {
      Enqueue(func, args...);
    }
  }

  size_t WorkerCount() const noexcept { return m_workers.size(); }

 protected:
  struct handler_tag {};
  struct member_tag {};

  template <class Handler>
  ThreadPoolBase(size_t worker_count, Handler handler, handler_tag)
      : ThreadPoolBase(worker_count) {
    for (size_t idx = 0; idx < worker_count; ++idx) {
      m_workers.emplace_back(handler);
    }
  }

  template <class MemFn>
  ThreadPoolBase(size_t worker_count, MemFn mem_fn, member_tag)
      : ThreadPoolBase(worker_count) {
    for (size_t idx = 0; idx < worker_count; ++idx) {
      m_workers.emplace_back(mem_fn, get_context());
    }
  }

  void execute() {
    for (;;) {
      async::ITask* task{nullptr};
      if (m_tasks.pop(task)) {
        std::unique_ptr<async::ITask> task_guard(task);
        task_guard->Process();
      } else if (m_controller.Stopped()) {
        break;
      } else {
        m_controller.Wait();
      }
    }
  }

  ConcretePool* get_context() { return get_context<ConcretePool>(this); }

  template <class PoolTy, class PoolBaseTy>
  static auto get_context(PoolBaseTy* base)
      -> std::enable_if_t<std::is_base_of_v<PoolBaseTy, PoolTy>, PoolTy*> {
    return static_cast<PoolTy*>(base);
  }

 private:
  ThreadPoolBase(size_t worker_count)
      : m_tasks(worker_count * QUEUE_CAPACITY_FACTOR) {
    m_workers.reserve(worker_count);
  }

 protected:
  std::vector<std::thread> m_workers;
  lockfree_queue m_tasks;
  ThreadController m_controller;
};

class ThreadPool : public ThreadPoolBase<ThreadPool> {
 public:
  using MyBase = ThreadPoolBase<ThreadPool>;

 public:
  ThreadPool(size_t worker_count)
      : MyBase(worker_count, &ThreadPool::execute, MyBase::member_tag{}) {}
};

class ThreadPoolWithNotify : public ThreadPoolBase<ThreadPoolWithNotify> {
 public:
  using MyBase = ThreadPoolBase<ThreadPoolWithNotify>;

 public:
  ThreadPoolWithNotify(size_t worker_count)
      : MyBase(worker_count,
               &ThreadPoolWithNotify::execute,
               MyBase::member_tag{}),
        m_counter{worker_count},
        m_initial_value{worker_count} {}

  void WaitForOne() {
    if (!m_counter) {
      std::unique_lock thread_waid_lock(m_mtx);
      size_t current_cnt{m_counter};
      m_wait_one.wait(thread_waid_lock,
                      [&counter = m_counter]() { return counter > 0; });
    }
  }

  void WaitForAll() {
    std::unique_lock thread_waid_lock(m_mtx);
    m_wait_one.wait(thread_waid_lock,
                    [&counter = m_counter, all_free = m_initial_value]() {
                      return counter == all_free;
                    });
  }

 protected:
  void execute() {
    for (;;) {
      async::ITask* task{nullptr};
      if (m_tasks.pop(task)) {
        acquire_counter();
        std::unique_ptr<async::ITask> task_guard(task);
        task_guard->Process();
        release_counter_and_notify();
      } else if (m_controller.Stopped()) {
        break;
      } else {
        m_controller.Wait();
      }
    }
  }

  void acquire_counter() { --m_counter; }

  void release_counter_and_notify() {
    auto result{++m_counter};
    m_wait_one.notify_all();
    if (result == m_initial_value) {
      m_wait_all.notify_all();
    }
  }

 protected:
  std::atomic_size_t m_counter{0};
  size_t m_initial_value{0};
  std::mutex m_mtx;
  std::condition_variable m_wait_one;
  std::condition_variable m_wait_all;
};
