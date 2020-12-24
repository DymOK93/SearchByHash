#pragma once
#include "handle_guard.hpp"
#include "synchronized.hpp"
#include "thread_pool.hpp"
#include "utils.h"
#include "winapi_typedefs.h"

#include "robin_hood.h"  // Included manually because vcpkg is using very old version now

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index_container.hpp>

#include <winioctl.h> /* For FSCTL */
#include <algorithm>
#include <filesystem>
#include <optional>
#include <queue>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

/************************************************************
 * Hash:
 * hash_result operator()(winapi::handle_t) const
 * Filter:
 * bool operator()(winapi::handle_t) const
 *
 * Instances of Hash and Filter
 * can be copied to parallelize operations
 ************************************************************/
namespace details {
template <class HashResult, class = void>
struct hash_length_in_bytes {
  static constexpr size_t value =
      sizeof(HashResult::value);  // HashResult::value must be char[] or
                                  // unsigned char[]
};

template <class HashResult>
struct hash_length_in_bytes<
    HashResult,
    std::void_t<decltype(HashResult::LENGTH_IN_BYTES)>> {
  static constexpr size_t value = HashResult::LENGTH_IN_BYTES;
};

template <class HashResult>
static constexpr size_t hash_length_in_bytes_v =
    hash_length_in_bytes<HashResult>::value;

template <template <class>
          class BasicHash,  /* std::hash or other with specialization for
                               std::string_view */
          class HashResult> /* Crypto hash */
struct CryptoHashToCppHash {
  size_t operator()(const HashResult& crypto_hash) const {
    std::string_view bytes_view(pointer_cast<char>(crypto_hash.value),
                                hash_length_in_bytes_v<HashResult>);
    return BasicHash<std::string_view>{}(bytes_view);
  }
};

}  // namespace details

namespace bmi = boost::multi_index;

template <class Hash, class Filter>
class NtfsHashIndex {
 public:
  using file_id_t = uint64_t;
  using file_path_ch_t = wchar_t; /* Wide characters are native for Windows */
  using file_path_buffer_t = std::wstring;
  using file_path_t = std::filesystem::path;
  using hash_t = Hash;
  using hash_result_t = std::invoke_result_t<hash_t, winapi::handle_t>;
  using filter_t = Filter;

  enum class ErrorCategory { Warning, Critical };

  struct Settings {
    char drive_letter;
    Hash hash;
    Filter filter;
  };

  struct ErrorLogEntry {
    ErrorLogEntry(ErrorCategory cat,
                  std::string msg)  // c-tor for Container::emplace()
        : category{cat}, message{std::move(msg)} {}

    ErrorCategory category;
    std::string message;
  };

  using settings_t = Settings;

  using error_log_entry_t = ErrorLogEntry;
  using error_log_t = std::queue<error_log_entry_t>;
  using sync_error_log_t = Synchronized<error_log_t>;

  template <typename Ty>
  using error_or_value = std::variant<error_log_entry_t, Ty>;

 private:
  struct IndexEntry {
    file_id_t file_id;        // File ID
    file_path_t native_path;  // Full path
    hash_result_t crypto_hash{};
  };

  using index_entry_t = IndexEntry;

  using hash_filter_bucket_t = std::pair<hash_t, filter_t>;
  using hash_filter_list_t = std::vector<hash_filter_bucket_t>;

  using mft_entry_t = MFT_ENUM_DATA;
  using sync_mft_request_t = Synchronized<mft_entry_t>;

  using usn_journal_id_t = uint64_t;
  using usn_record_id_t = USN;

  struct UsnJournalHeader {
    usn_journal_id_t id;
    usn_record_id_t next;
  };

  using usn_header_t = UsnJournalHeader;
  using sync_usn_header_t = Synchronized<usn_header_t>;
  using usn_native_header_t = USN_JOURNAL_DATA;
  using usn_journal_create_t = CREATE_USN_JOURNAL_DATA;
  using usn_data_request_t = READ_USN_JOURNAL_DATA;
  using usn_entry_t = USN_RECORD;

  using file_name_info_t = FILE_NAME_INFO;
  using qword_aligned_buffer = winapi::buf_t<winapi::qword_t>;

 private:
  using thread_pool_t = ThreadPool;

  struct id_tag {};
  struct hash_tag {};

  using internal_hash_t =
      details::CryptoHashToCppHash<std::hash, hash_result_t>;

  using file_map_t = bmi::multi_index_container<
      index_entry_t,
      bmi::indexed_by<
          bmi::hashed_unique<  // NTFS file numbers are unique
              bmi::tag<id_tag>,
              bmi::member<index_entry_t, uint64_t, &index_entry_t::file_id>>,
          bmi::hashed_non_unique<bmi::tag<hash_tag>,  // Hashes of content are
                                                      // not unique
                                 bmi::member<index_entry_t,
                                             hash_result_t,
                                             &index_entry_t::crypto_hash>,
                                 internal_hash_t>>>;
  using sync_file_map_t = Synchronized<file_map_t>;

  static constexpr size_t MIN_THREAD_COUNT{2}, MAX_ERROR_LOG_SIZE{1000};
  static inline const size_t BASIC_THREAD_COUNT{
      std::thread::hardware_concurrency()};

  static constexpr size_t MAX_PATH_LENGTH{32'767u},  // Wide characters
      FILE_PATH_BUFFER_LENGTH{MAX_PATH_LENGTH + sizeof(file_name_info_t) /
                                                    sizeof(file_path_ch_t)};
  static constexpr size_t DEFAULT_MFT_ENUM_CHUNK_SIZE{
      1024ull * 1024ull},                    // 1mb chunk for file enumeration
      DEFAULT_USN_READ_CHUNK_SIZE{1024ull};  // 1kb chunk for reading USN

  static constexpr size_t USN_JOURNAL_MAX_SIZE{1024ull * 1024ull *
                                               64ull},          // 64mb
      USN_JOURNAL_ALLOCATION_DELTA{1024ull * 1024ull * 16ull},  // 16 mb
      USN_JOURNAL_MIN_VERSION{0},
      USN_JOURNAL_MAX_VERSION{2};  // V3+ uses 128-bit ID

  static constexpr winapi::dword_t USN_JOURNAL_MASK{
      USN_REASON_DATA_EXTEND | USN_REASON_DATA_OVERWRITE |
      USN_REASON_DATA_TRUNCATION | USN_REASON_ENCRYPTION_CHANGE |
      USN_REASON_FILE_CREATE | USN_REASON_FILE_DELETE |
      USN_REASON_RENAME_NEW_NAME};

 public:
  using const_index_range =
      decltype(std::declval<file_map_t>().get<hash_tag>().equal_range(
          std::declval<hash_result_t>()));

 public:
  template <class HashTy, class FilteTy>
  NtfsHashIndex(char drive_letter, const HashTy& hash, const FilteTy& filter)
      : m_volume{open_mounted_volume(drive_letter)},
        m_th_pool(calculate_thread_count()),  // m_th_pool and m_hf_list be the
                                              // same size
        m_hf_list(
            make_hash_filter_list(hash, filter, calculate_thread_count())) {
    if (auto fs_flags = get_volume_flags(m_volume.get()); !fs_flags) {
      throw std::runtime_error(
          make_system_error_message("Unable to get volume flags"));
    } else if (!check_usn_and_open_by_id_support(*fs_flags)) {
      throw std::runtime_error(
          make_system_error_message("Volume has unsupported filesystem"));
    }
    m_journal = try_getting_usn_header(
        m_volume.get(),
        m_error_log);  // Missing a journal isn't a critical error
    m_file_map =
        make_ntfs_index(m_volume.get(), m_th_pool, m_hf_list, m_error_log);
  }

  NtfsHashIndex(const settings_t& settings)
      : NtfsHashIndex(setting.drive_letter, settings.hash, settings.filter) {}

  std::vector<std::wstring_view> GetPathList(
      const hash_result_t& target) const {
    auto [first, last]{equal_range(target)};

    std::vector<std::wstring_view> path_list;
    std::transform(
        first, last, std::back_inserter(path_list),
        [&path_list](const index_entry_t& index_entry) -> std::wstring_view {
          return index_entry.native_path.c_str();
        });

    return path_list;
  }

  const_index_range equal_range(const hash_result_t& target) const {
    update_index_if_avaliable();
    auto [guard, file_map]{m_file_map.GetAccess()};
    auto& index{file_map.get<hash_tag>()};
    return index.equal_range(target);
  }

 private:
  static size_t calculate_thread_count() {
    return (std::max)(
        MIN_THREAD_COUNT,
        BASIC_THREAD_COUNT);  // hardware_concurrency() can return 0
  }

  static file_map_t make_ntfs_index(winapi::handle_t volume_handle,
                                    thread_pool_t& workers,
                                    hash_filter_list_t& hf_list,
                                    sync_error_log_t& error_log) {
    sync_mft_request_t shared_request{std::in_place_t{}, make_mft_request(0)};
    sync_file_map_t file_map;
    std::vector<std::future<void>> tasks;
    tasks.reserve(std::size(hf_list));

    for (auto& hf_bucket : hf_list) {
      tasks.push_back(workers.Schedule(
          make_exception_filter(&filter_and_hash_files, error_log),
          volume_handle, std::ref(shared_request), std::ref(file_map),
          std::ref(hf_bucket), std::ref(error_log)));
    }
    wait_for_all(tasks);  // Wait for the tasks to complete
    return std::move(
        file_map.GetAccess()
            .ref_to_value);  // mutex is non-copyable and non-movable
  }

  static void filter_and_hash_files(winapi::handle_t volume,
                                    sync_mft_request_t& shared_request,
                                    sync_file_map_t& output_map,
                                    hash_filter_bucket_t& hf_entry,
                                    sync_error_log_t& log) {
    qword_aligned_buffer usn_buffer(round_up_by_8(DEFAULT_MFT_ENUM_CHUNK_SIZE));
    file_path_buffer_t path_buffer(FILE_PATH_BUFFER_LENGTH, 0);

    for (;;) {
      auto [bytes_read, first]{get_ntfs_raw_file_info_and_update_request(
          volume, shared_request, usn_buffer)};
      if (!bytes_read) {
        break;
      }
      unsigned char* last{first + bytes_read};

      while (first < last) {
        auto* usn_entry{pointer_cast<usn_entry_t>(first)};
        first += usn_entry->RecordLength;

        file_id_t file_id{extract_file_number(usn_entry)};  // Get NTFS file ID
        if (auto index_entry =
                handle_file_by_id(volume, file_id, hf_entry, path_buffer, log);
            index_entry) {
          output_map.GetAccess().ref_to_value.insert(std::move(*index_entry));
        }
      }
    }
  }

  template <typename FirstFieldTy,
            typename InputTy,
            class Updater>  // result_type Updater::operator()(UnsyncRequestTy&,
                            // FirstFieldTy) required
  static std::pair<size_t, unsigned char*> extract_raw_filesystem_info(
      winapi::handle_t volume_handle,
      winapi::dword_t control_code,
      InputTy& request,
      qword_aligned_buffer& buffer,
      Updater request_updater) {  // Updates shared info

    winapi::dword_t result{
        read_raw_filesystem_info(volume_handle, control_code, request, buffer)};

    unsigned char* first_entry{nullptr};

    if (result) {
      std::invoke(request_updater, request,
                  *pointer_cast<FirstFieldTy>(
                      std::data(buffer)));  // Updated must be called under lock
      result -= sizeof(FirstFieldTy);       // Decrease summary size
      first_entry =
          pointer_cast<unsigned char>(std::data(buffer)) + sizeof(FirstFieldTy);
    }
    return std::make_pair(result, first_entry);
  }

  template <typename InputTy>
  static winapi::dword_t read_raw_filesystem_info(
      winapi::handle_t volume_handle,
      winapi::dword_t control_code,
      InputTy& input,
      qword_aligned_buffer& buffer) {
    static_assert(std::is_trivially_copyable_v<InputTy>,
                  "Input buffer object must be trivially copyable");
    winapi::dword_t bytes_read{0};
    if (!DeviceIoControl(volume_handle, control_code, /* CTL Code */
                         std::addressof(input),       /* Input buffer */
                         sizeof(InputTy),             /* Input buffer size */
                         std::data(buffer),           /* Output buffer */
                         static_cast<winapi::dword_t>(
                             std::size(buffer) *
                             sizeof(winapi::qword_t)), /* Output buffer size */
                         std::addressof(bytes_read),   /* Feedback */
                         nullptr /* Synchronous*/)) {
      bytes_read = 0;
    }
    return bytes_read;
  }

  static std::pair<size_t, unsigned char*>
  get_ntfs_raw_file_info_and_update_request(winapi::handle_t volume_handle,
                                            sync_mft_request_t& shared_request,
                                            qword_aligned_buffer& buffer) {
    auto [guard, request]{shared_request.GetAccess()};
    return extract_raw_filesystem_info<file_id_t>(
        volume_handle, FSCTL_ENUM_USN_DATA, request, buffer,
        [](mft_entry_t& raw_request, file_id_t next_id) {
          raw_request.StartFileReferenceNumber =
              next_id;  // request == shared_request.GetAccess().ref_to_value
        });
  }

  static std::pair<size_t, unsigned char*>
  get_usn_journal_data_and_update_request(winapi::handle_t volume_handle,
                                          sync_usn_header_t& shared_header,
                                          qword_aligned_buffer& buffer) {
    auto [guard, header]{shared_header.GetAccess()};
    auto request{make_usn_journal_request(header)};

    return extract_raw_filesystem_info<usn_record_id_t>(
        volume_handle, FSCTL_READ_USN_JOURNAL, request, buffer,
        [&header](auto& _dummy, usn_record_id_t next_id) {
          header.next =
              next_id;  // request != shared_request.GetAccess().ref_to_value
        });
  }

  static winapi::handle_guard_t open_mounted_volume(char letter) {
    winapi::static_charbuf_t<7> buffer{
        "\\\\.\\X:"};  // 4 characters + letter + : + '\0' = 7
    buffer[4] = letter;
    auto raw_handle{CreateFileA(std::data(buffer), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,  // No additional flags
                                nullptr)};
    if (raw_handle == INVALID_HANDLE_VALUE) {
      throw std::runtime_error("Volume is protected or unavaliable");
    }
    return winapi::MakeHandleGuard(raw_handle);
  }

  static bool check_usn_and_open_by_id_support(winapi::dword_t fs_flags) {
    return (fs_flags & FILE_SUPPORTS_OPEN_BY_FILE_ID) &&
           (fs_flags & FILE_SUPPORTS_USN_JOURNAL);
  }

  static std::optional<winapi::dword_t> get_volume_flags(
      winapi::handle_t volume) {
    winapi::static_buf_t<file_path_ch_t, MAX_PATH + 1> volume_name, fs_name;
    winapi::dword_t serial_number, max_component_length, fs_flags;
    if (!GetVolumeInformationByHandleW(
            volume, std::data(volume_name),
            static_cast<winapi::dword_t>(std::size(volume_name) *
                                         sizeof(file_path_ch_t)),
            std::addressof(serial_number), std::addressof(max_component_length),
            std::addressof(fs_flags), std::data(fs_name),
            static_cast<winapi::dword_t>(std::size(fs_name) *
                                         sizeof(file_path_ch_t)))) {
      return std::nullopt;
    }
    return fs_flags;
  }

  static mft_entry_t make_mft_request(file_id_t base_idx) {
    mft_entry_t entry{};  // Fields may be changed in future
    entry.StartFileReferenceNumber = base_idx;
    entry.MinMajorVersion = USN_JOURNAL_MIN_VERSION;
    entry.MaxMajorVersion = USN_JOURNAL_MAX_VERSION;
    return entry;
  }

  static std::optional<index_entry_t> handle_file_by_id(
      winapi::handle_t volume,
      file_id_t file_id,
      hash_filter_bucket_t& hf_entry,
      file_path_buffer_t& preallocated_buffer,
      sync_error_log_t& err_log) {
    auto& [hash, filter]{hf_entry};

    // Pattern "chain" ("pipeline") will be helpful... I'll do it later :(

    auto handle_or_err{open_file_for_reading_by_id(volume, file_id)};
    if (is_error_log(handle_or_err)) {
      push_error_log(err_log, std::move(get_error_log(handle_or_err)));
    } else {
      auto raw_handle{
          get_value(handle_or_err)
              .get()};  // handle_guard_t isn't copyable but handle_t is
      if (filtrate(filter, raw_handle)) {  // Filtering
        auto path_or_err{get_full_path(raw_handle, preallocated_buffer)};
        if (is_error_log(path_or_err)) {
          push_error_log(err_log, std::move(get_error_log(path_or_err)));
        } else {
          return make_index_entry(file_id, std::move(get_value(path_or_err)),
                                  make_hash_of_file(hash, raw_handle));
        }
      }
    }
    return std::nullopt;
  }

  static bool filtrate(filter_t& filter, winapi::handle_t handle) {
    return std::invoke(filter, handle);
  }

  static error_or_value<winapi::handle_guard_t> open_file_for_reading_by_id(
      winapi::handle_t volume,
      file_id_t file_id) {
    FILE_ID_DESCRIPTOR id_desc{};
    id_desc.dwSize = sizeof(FILE_ID_DESCRIPTOR);
    id_desc.Type = FileIdType;  // 64-bit ID
    id_desc.FileId.QuadPart = file_id;
    auto raw_handle{OpenFileById(
        volume, std::addressof(id_desc), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        FILE_FLAG_SEQUENTIAL_SCAN  // For improve hashing speed
        )};
    if (raw_handle == INVALID_HANDLE_VALUE) {
      return ErrorLogEntry{ErrorCategory::Critical,
                           make_system_error_message("Invalid file handle: ")};
    }
    return winapi::MakeHandleGuard(raw_handle);
  }

  static index_entry_t make_index_entry(file_id_t file_id,
                                        file_path_t&& path, /* Move only */
                                        const hash_result_t& hash) {
    return {file_id, std::move(path), hash};
  }

  static hash_result_t make_hash_of_file(hash_t& hash,
                                         winapi::handle_t file_handle) {
    return std::invoke(hash, file_handle);
  }

  static error_or_value<file_path_t> get_full_path(
      winapi::handle_t file_handle,
      file_path_buffer_t& preallocated_buffer /*FILE_PATH_BUFFER_LENGTH*/) {
    if (!GetFileInformationByHandleEx(
            file_handle, FileNameInfo, std::data(preallocated_buffer),
            static_cast<winapi::dword_t>(
                std::size(preallocated_buffer) *
                sizeof(file_path_ch_t)))) {  // Size in bytes
      return ErrorLogEntry{ErrorCategory::Critical,
                           make_system_error_message("Unable to get path")};
    }
    auto file_name_info{
        pointer_cast<file_name_info_t>(std::data(preallocated_buffer))};
    return file_path_t(file_path_buffer_t(
        file_name_info->FileName,
        file_name_info->FileNameLength / sizeof(file_path_ch_t)));
  }

  static file_id_t extract_file_number(usn_entry_t* raw_usn) {
    return raw_usn->FileReferenceNumber;
  }

  static constexpr size_t round_up_by_8(size_t value) {
    size_t result{value / 8};
    return (value & 0x7)
               ? result + 1  // value & 0111b != 0 -> not divisible by 8
               : result;
  }

  static constexpr size_t rotate_index(size_t min, size_t max, size_t current) {
    return current == max ? min : current + 1;
  }

  template <typename Ty>
  static constexpr bool is_error_log(const error_or_value<Ty>& message) {
    return std::holds_alternative<error_log_entry_t>(message);
  }

  template <typename Ty>
  static constexpr error_log_entry_t& get_error_log(
      error_or_value<Ty>& message) {
    return std::get<error_log_entry_t>(message);
  }

  template <typename Ty>
  static constexpr Ty& get_value(error_or_value<Ty>& message) {
    return std::get<Ty>(message);
  }

  template <class HashTy, class FilterTy>
  hash_filter_list_t make_hash_filter_list(const HashTy& hash,
                                           const FilterTy& filter,
                                           size_t requested_size) {
    return {requested_size, std::make_pair(hash, filter)};
  }

  template <class FutureList>
  static void wait_for_all(const FutureList& futures) {
    for (const auto& task : futures) {
      task.wait();
    }
  }

  static std::pair<usn_header_t, bool> try_getting_usn_header(
      winapi::handle_t volume_handle,
      sync_error_log_t& err_log) {
    auto result{get_usn_journal_header(volume_handle)};
    if (is_error_log(result)) {
      push_error_log(err_log, std::move(get_error_log(result)));
      return std::make_pair(usn_header_t{}, false);
    }
    return std::make_pair(get_value(result), true);
  }

  static error_or_value<usn_header_t> get_usn_journal_header(
      winapi::handle_t volume_handle) {
    if (!create_usn_journal(
            volume_handle)) {  // We nead to create journal if it exists
      return ErrorLogEntry(
          ErrorCategory::Critical,
          make_system_error_message("Unable to create USN journal"));
    }
    auto header_holder{query_existing_usn_header(volume_handle)};

    if (!header_holder) {
      return ErrorLogEntry(
          ErrorCategory::Critical,
          make_system_error_message("Unable to query USN journal"));
    }
    return *header_holder;
  }

  static bool create_usn_journal(winapi::handle_t volume_handle) {
    usn_journal_create_t create{USN_JOURNAL_MAX_SIZE,
                                USN_JOURNAL_ALLOCATION_DELTA};
    winapi::dword_t bytes_returned;
    return bool_cast(DeviceIoControl(
        volume_handle, FSCTL_CREATE_USN_JOURNAL, std::addressof(create),
        sizeof(usn_journal_create_t), nullptr, /* No output buffer */
        0, std::addressof(bytes_returned), nullptr));
  }

  static std::optional<usn_header_t> query_existing_usn_header(
      winapi::handle_t volume_handle) {
    winapi::dword_t bytes_returned;
    usn_native_header_t native_header;

    if (!DeviceIoControl(volume_handle, FSCTL_QUERY_USN_JOURNAL, nullptr,
                         0, /* No input buffer */
                         std::addressof(native_header), sizeof(native_header),
                         std::addressof(bytes_returned), nullptr)) {
      return std::nullopt;
    }
    return usn_header_t{native_header.UsnJournalID, native_header.NextUsn};
  }

  static usn_data_request_t make_usn_journal_request(
      usn_header_t header) {  // sizeof(usn_header_t) <= 16, let's pass by value
    usn_data_request_t request{};
    request.MinMajorVersion = USN_JOURNAL_MIN_VERSION;
    request.MaxMajorVersion = USN_JOURNAL_MAX_VERSION;
    request.UsnJournalID = header.id;
    request.StartUsn = header.next;
    request.ReasonMask = USN_JOURNAL_MASK;
    return request;
  }

  static std::string make_system_error_message(std::string_view msg_base) {
    std::string msg(msg_base);
    if (!msg.empty()) {
      msg += '\n';
    }
    msg += "System error code: ";
    msg += std::to_string(GetLastError());
    return msg;
  }

  void update_index_if_avaliable() const {
    if (m_journal.second) {  // Check flag
      update_index();
    }
  }

  void update_index() const {  // Locked operation
    std::vector<std::future<void>> tasks;
    tasks.reserve(std::size(m_hf_list));

    for (auto& hf_bucket : m_hf_list) {
      tasks.push_back(m_th_pool.Schedule(
          make_exception_filter(&update_index_entries, m_error_log),
          m_volume.get(), std::ref(m_journal.first), std::ref(m_file_map),
          std::ref(hf_bucket), std::ref(m_error_log)));
    }
    wait_for_all(tasks);  // Wait for the tasks to complete
  }

  static void update_index_entries(winapi::handle_t volume,
                                   sync_usn_header_t& shared_request,
                                   sync_file_map_t& output_map,
                                   hash_filter_bucket_t& hf_entry,
                                   sync_error_log_t& log) {
    qword_aligned_buffer usn_buffer(round_up_by_8(DEFAULT_USN_READ_CHUNK_SIZE));
    file_path_buffer_t path_buffer(FILE_PATH_BUFFER_LENGTH, 0);

    robin_hood::unordered_flat_map<file_id_t, winapi::dword_t>
        file_actions;  // Flags storage

    for (;;) {
      auto [bytes_read, first]{get_usn_journal_data_and_update_request(
          volume, shared_request, usn_buffer)};
      if (!bytes_read) {
        break;
      }
      collect_usn_entries_flags(first, first + bytes_read, file_actions);

      for (const auto& [file_id, flags] : file_actions) {
        if ((flags & USN_REASON_FILE_DELETE) ||
            (flags & USN_REASON_FILE_CREATE)) {
          output_map.GetAccess().ref_to_value.erase(file_id);
          if (auto index_entry =
                  handle_file_by_id(volume, file_id, hf_entry, path_buffer,
                                    log);  // Fails if doesn't exists
              index_entry) {
            output_map.GetAccess().ref_to_value.insert(std::move(*index_entry));
          }
        } else {
          if (flags &
              (USN_REASON_DATA_EXTEND | USN_REASON_DATA_OVERWRITE |
               USN_REASON_DATA_TRUNCATION | USN_REASON_ENCRYPTION_CHANGE)) {
            try_rehashing_or_erasing(volume, file_id, output_map, hf_entry,
                                     log);
          }
          if (flags & USN_REASON_RENAME_NEW_NAME) {
            try_renaming(volume, file_id, output_map, path_buffer, log);
          }
        }
      }

      file_actions.clear();
    }
  }

  template <class FlagMap>
  static void collect_usn_entries_flags(unsigned char* first,
                                        unsigned char* last,
                                        FlagMap& actions) {
    while (first < last) {
      auto* usn_entry{pointer_cast<usn_entry_t>(first)};
      first += usn_entry->RecordLength;
      actions[extract_file_number(usn_entry)] |= usn_entry->Reason;
    }
  }

  static void try_renaming(winapi::handle_t volume_handle,
                           file_id_t file_id,
                           sync_file_map_t& output_map,
                           file_path_buffer_t& path_buffer,
                           sync_error_log_t& err_log) {
    auto handle_or_err{open_file_for_reading_by_id(volume_handle, file_id)};
    if (is_error_log(handle_or_err)) {
      push_error_log(err_log, std::move(get_error_log(handle_or_err)));
    } else {
      modify_existing_entry(output_map, file_id,
                            make_file_renamer(get_value(handle_or_err).get(),
                                              path_buffer, err_log));
    }
  }

  static auto make_file_renamer(winapi::handle_t raw_handle,
                                file_path_buffer_t& path_buffer,
                                sync_error_log_t& err_log) {
    return [raw_handle, &err_log, &path_buffer](
               index_entry_t&
                   existing_entry) mutable {  // handle must be non-const
      auto path_or_err{get_full_path(raw_handle, path_buffer)};
      if (is_error_log(path_or_err)) {
        push_error_log(err_log, std::move(get_error_log(path_or_err)));
      } else {
        existing_entry.native_path = std::move(get_value(path_or_err));
      }
    };
  }

  static void try_rehashing_or_erasing(winapi::handle_t volume_handle,
                                       file_id_t file_id,
                                       sync_file_map_t& output_map,
                                       hash_filter_bucket_t& hf_bucket,
                                       sync_error_log_t& err_log) {
    auto handle_or_err{open_file_for_reading_by_id(volume_handle, file_id)};
    if (is_error_log(handle_or_err)) {
      push_error_log(err_log, std::move(get_error_log(handle_or_err)));
    } else {
      auto& [hash, filter]{hf_bucket};
      auto raw_handle{get_value(handle_or_err).get()};
      if (!filtrate(filter, raw_handle)) {
        output_map.GetAccess().ref_to_value.erase(file_id);  // Erase element
      } else {
        modify_existing_entry(output_map, file_id,
                              make_file_rehasher(raw_handle, hash));
      }
    }
  }

  static auto make_file_rehasher(winapi::handle_t file_handle, hash_t& hash) {
    // Pattern "chain" ("pipeline") will be helpful... I'll do it later :(
    return [file_handle, &hash](index_entry_t& existing_entry) {
      existing_entry.crypto_hash = make_hash_of_file(hash, file_handle);
    };
  }

  template <class Handler>
  static void modify_existing_entry(sync_file_map_t& output_map,
                                    file_id_t id,
                                    Handler&& handler) {
    auto [guard, fmap]{output_map.GetAccess()};
    auto& index{fmap.get<id_tag>()};
    auto it{index.find(id)};
    if (it != std::end(fmap)) {
      index.modify(it, handler);
    }
  }

  template <class Handler>
  static auto make_exception_filter(
      Handler&& handler,
      sync_error_log_t&
          error_log) {  // Functor which passes args and catches all exceptions.
                        // Well... bad_alloc in error_log. Hmm :)
    return [&error_log, func = std::forward<Handler>(handler)](auto&&... args) {
      try {
        std::invoke(func, std::forward<decltype(args)>(args)...);
      } catch (const std::exception& exc) {
        push_error_log(error_log, ErrorCategory::Critical, exc.what());
      } catch (...) {
        push_error_log(error_log, ErrorCategory::Critical, "Unknown exception");
      }
    };
  }

  template <class... Types>
  static void push_error_log(sync_error_log_t& err_log, Types&&... args) {
    auto [guard, log]{err_log.GetAccess()};
    if (std::size(log) > MAX_ERROR_LOG_SIZE) {
      log.pop();
    }
    log.emplace(std::forward<Types>(args)...);
  }

 private:
  winapi::handle_guard_t m_volume;
  mutable thread_pool_t m_th_pool;
  mutable hash_filter_list_t m_hf_list;
  mutable sync_error_log_t m_error_log;
  mutable sync_file_map_t m_file_map;
  mutable std::pair<sync_usn_header_t, bool> m_journal;
};

template <class Hash, class Filter>
NtfsHashIndex(char drive_letter, const Hash& hash, const Filter& filter)
    -> NtfsHashIndex<Hash, Filter>;  // CTAD guide

template <class Hash, class Filter>
auto MakeNtfsHashIndex(char drive_letter,
                       const Hash& hash,
                       const Filter& filter)
    -> NtfsHashIndex<Hash,      // Index-generating
                     Filter> {  // function
  return NtfsHashIndex<Hash, Filter>(drive_letter, hash, filter);
}
