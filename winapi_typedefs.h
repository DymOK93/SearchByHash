#pragma once
#include <array>
#include <string>
#include <type_traits>
#include <vector>
#include <Windows.h>

namespace winapi {
using handle_t = HANDLE;
using dword_t = DWORD;
using qword_t = DWORDLONG;
using id_t = dword_t;
using bool_t = BOOL;
using boolean_t = BOOLEAN;
using atomic32_t = volatile unsigned long;
using byte = unsigned char;

template <typename Ty>
using buf_t = std::vector<Ty>;

using charbuf_t = std::string;
using wcharbuf_t = std::wstring;

template <typename Ty, size_t N>
using static_buf_t = std::array<Ty, N>;

template <size_t N>
using static_charbuf_t = std::array<char, N>;
template <size_t N>
using static_wcharbuf_t = std::array<wchar_t, N>;

template <size_t N, size_t Align>
using static_aligned_buf_t = std::aligned_storage_t<N, Align>;
}  // namespace winapi