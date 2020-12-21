#include "SearchByHash.h"
#include "disk_hash_index.hpp"
#include "hash_wrapper.hpp"

#include <Windows.h>
#include <conio.h>
using namespace std;

int main() {
  try {
    StartSearch('C');
  } catch (const exception& exc) {
    wcout << "Critical internal error occurred. Try restarting program with "
             "administrator rights\n";
    wcout << "Message: " << exc.what() << '\n';
  }
  return 0;
}

auto MakeHasher() {
  return [engine = crypto::Sha256{}](winapi::handle_t handle) mutable {
    return engine.HashFile(handle);
  };
}

auto MakeFilter() {
  return [](winapi::handle_t handle) {
    FILE_ATTRIBUTE_TAG_INFO attrs{};
    GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attrs,
                                 sizeof(attrs));
    if ((attrs.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      return false;
    }
    LARGE_INTEGER val;
    GetFileSizeEx(handle, &val);
    return val.QuadPart <= 1024ull * 1024ull;  // 1mb
  };
}

crypto::Sha256Result RequestUserHash() {
  wcout << "Enter target SHA256 hash: ";
  return crypto::Sha256FromIstream(cin);
}

void StartSearch(char drive_letter) {
  wcout << "Starting search engine...\n";  // wcout supports char* strings
  wcout
      << "Search system is indexing drive " << drive_letter
      << ":\\ now. It depends on the number of files on the drive and can take "
         "a long time (up to half an hour). Please wait ...\n";
  auto search_engine{
      MakeNtfsHashIndex(drive_letter, MakeHasher(), MakeFilter())};
  wcout << "Disk indexing successully finished!\n";
  for (;;) {
    wcout << "Enter 0 to exit or another number to continue search...\n";
    int mode;
    cin >> mode;
    if (mode == 0) {
      break;
    }
    FlushLine(cin);  // Сleaning of service characters
    try {
      auto target{RequestUserHash()};
      auto result{search_engine.GetPathList(target)};
      if (result.empty()) {
        wcout << "(nothing found)\n";
      } else {
        PrintPathList(wcout, drive_letter, result);
      }
    } catch (const exception& exc) {
      wcout << "Unexpected error occurred. Check your input and try again\n";
      wcout << "Message: " << exc.what() << '\n';
    }
  }
}
