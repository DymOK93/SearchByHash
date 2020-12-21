#pragma once
#include "utils.h"
#include "winapi_typedefs.h"

#include <cryptopp/sha.h>

#include <Windows.h>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace crypto {
template <size_t length>
struct HashResult {
  static constexpr size_t LENGTH_IN_BYTES = length;
  static constexpr size_t LENGTH_IN_CHARACTERS =
      2 * length;  // 2 Hex-символа - 1 байт
  unsigned char value[length];
};

namespace details {
template <size_t length>
bool compare(const HashResult<length>& lhs, const HashResult<length>& rhs) {
  return std::memcmp(lhs.value, rhs.value, length);
}
}  // namespace details

template <size_t length>
bool operator==(const HashResult<length>& lhs, const HashResult<length>& rhs) {
  return details::compare(lhs, rhs) ==
         0;  // Т.к. качестве функции сравнения используется memcmp
}

namespace details {
template <class Number>
std::from_chars_result read_as_hex_unchecked(const char* str, Number& val) {
  return std::from_chars(str, str + 2 * sizeof(Number),
                         val,  // 2 Hex-символа - 1 байт
                         16);
}

template <class Number>
const char* read_as_hex(const char* str, Number& val) {
  if (auto [new_base, error_code] = read_as_hex_unchecked(str, val);
      static_cast<size_t>(error_code)) {  // 0 - отсутствие ошибки
    throw std::runtime_error("Invalid hex value");
  } else {
    str = new_base;
  }
  return str;
}

template <class Number>
std::from_chars_result read_array_as_hex_unckecked(const char* str,
                                                   Number* data,
                                                   size_t count) {
  std::from_chars_result result;
  for (size_t idx = 0; idx < count; ++idx) {
    result = read_as_hex_unchecked(str, data[idx]);
    if (result.ec) {  // Не 0 -> ошибка
      break;
    }
  }
  return result;
}

template <class Number>
const char* read_array_as_hex(const char* str, Number* data, size_t count) {
  for (size_t idx = 0; idx < count; ++idx) {
    str = read_as_hex(str, data[idx]);
  }
  return str;
}
}  // namespace details

template <size_t length>
std::istream& operator<<(std::istream& input, HashResult<length>& hash) {
  using hash_result_t = HashResult<length>;
  char buffer[hash_result_t::LENGTH_IN_CHARACTERS + 1];  // Для нуль-терминатора
  input.get(buffer, sizeof(buffer));
  details::read_array_as_hex(buffer, hash.value, length);
  return input;
}

template <class CryptoPPHash>
class HashWrapper {
 public:
  using hash_t = CryptoPPHash;
  using byte = CryptoPP::byte;

  static constexpr size_t HASH_LENGTH{hash_t::DIGESTSIZE};

  using hash_result_t = HashResult<HASH_LENGTH>;

 private:
  using byte_buffer_t = std::vector<byte>;
  static constexpr size_t DEFAULT_BUFFER_SIZE{1024u * 1024u};

 public:
  HashWrapper() = default;

  hash_result_t HashRawBytes(std::string_view raw_chars) {
    return calculate_hash_of_raw_bytes(data(raw_chars), size(raw_chars));
  }

  hash_result_t HashFile(std::string_view path) {
    return calculate_hash_of_file_by_path(path);
  }

  hash_result_t HashFile(const std::filesystem::path& path) {
    return calculate_hash_of_file_by_path(path);
  }

  hash_result_t HashFile(winapi::handle_t raw_file_handle) {
    return calculate_hash_of_file_by_handle(raw_file_handle);
  }

 private:
  template <class PathTy>
  hash_result_t calculate_hash_of_file_by_path(const PathTy& path) {
    auto file_stream{make_binary_ifstream(path)};
    return calculate_hash_of_file(m_hash, make_ifstream_reader(file_stream),
                                  DEFAULT_BUFFER_SIZE);
  }

  hash_result_t calculate_hash_of_file_by_handle(
      winapi::handle_t raw_file_handle) {
    return calculate_hash_of_file(m_hash, make_winfile_reader(raw_file_handle),
                                  DEFAULT_BUFFER_SIZE);
  }

  template <typename Ty>
  hash_result_t calculate_hash_of_raw_bytes(Ty* sequence,
                                            size_t length_in_bytes) {
    hash_result_t result{};
    m_hash.CalculateDigest(pointer_cast<byte>(result.value),
                           pointer_cast<CryptoPP::byte>(sequence),
                           length_in_bytes);
    return result;
  }

  template <class PathTy>
  static std::ifstream make_binary_ifstream(const PathTy& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
      throw std::runtime_error("Unable to open file");
    }
    file.tie(nullptr);
    file.sync_with_stdio(false);  // Отключение синзронизации для ускорения IO
    return file;
  }

  template <class Reader>
  static hash_result_t calculate_hash_of_file(
      CryptoPPHash& hash,
      Reader stream_reader,  // Считывает данные в буфер byte_buffer_t& и
      size_t buffer_size) {  // возвращает объем считанного в байтах

    hash_result_t result{};
    byte_buffer_t buffer(buffer_size);

    for (;;) {
      size_t count{stream_reader(buffer, buffer_size)};
      if (!count) {
        break;
      }
      hash.Update(data(buffer), count);
    }
    hash.Final(pointer_cast<byte>(result.value));
    return result;
  }

  static auto make_ifstream_reader(std::ifstream& input) {
    return [&input](byte_buffer_t& buffer,
                    size_t requested_bytes_count) -> size_t {
      input.read(pointer_cast<char>(std::data(buffer)), requested_bytes_count);
      return input
          .gcount();  // Статистика последней операции неформатированного ввода
    };
  }

  static auto make_winfile_reader(winapi::handle_t raw_file_handle) {
    return [raw_file_handle](byte_buffer_t& buffer,
                             size_t requested_bytes_count) mutable -> size_t {
      winapi::dword_t bytes_read;
      if (!ReadFile(raw_file_handle, std::data(buffer),
                    static_cast<winapi::dword_t>(requested_bytes_count),
                    std::addressof(bytes_read), nullptr)) {
        throw std::runtime_error("Unable to read file");
      }
      return bytes_read;
    };
  }

 private:
  CryptoPPHash m_hash;
};

using Sha256 = HashWrapper<CryptoPP::SHA256>;
using Sha256Result = typename Sha256::hash_result_t;

Sha256Result Sha256FromIstream(std::istream& input) {
  Sha256Result result;
  input << result;
  return result;
}
}  // namespace crypto
