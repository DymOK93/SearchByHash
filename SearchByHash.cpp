#include "SearchByHash.h"
#include "disk_hash_index.hpp"
#include "hash_wrapper.hpp"

#include <Windows.h>
#include <conio.h>
using namespace std;

int main(int argc, char* argv[]) {
  if (argc != 3) {
    wcout << "Usage: SearchByHash <volume> <max_size>\n";
  } else {
    try {
      StartSearch(argv[1][0], stoll(argv[2]));
    } catch (const exception& exc) {
      wcout << "Critical internal error occurred. Check command line arguments "
               "and try restarting program with administrator rights\n";
      wcout << "Message: " << exc.what() << '\n';
    }
  }
  return 0;
}

auto MakeHasher() {
  return [engine = crypto::Sha256{}](winapi::handle_t handle) mutable {
    return engine.HashFile(handle);
  };
}

auto MakeFilter(size_t max_file_size) {
  return [max_file_size](winapi::handle_t handle) {
    FILE_ATTRIBUTE_TAG_INFO attrs{};
    GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attrs,
                                 sizeof(attrs));
    if ((attrs.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      return false;
    }
    LARGE_INTEGER val;
    GetFileSizeEx(handle, &val);
    return static_cast<size_t>(val.QuadPart) <= max_file_size;
  };
}

crypto::Sha256Result RequestUserHash() {
  wcout << "Enter target SHA256 hash: ";
  return crypto::Sha256FromIstream(cin);
}

void StartSearch(char drive_letter, size_t max_file_size) {
  wcout << "Starting search engine...\n";  // wcout supports char* strings
  wcout
      << "Search system is indexing drive " << drive_letter
      << ":\\ now. It depends on the number of files on the drive and can take "
         "a long time (up to half an hour). Please wait ...\n";
  auto search_engine{
      MakeNtfsHashIndex(drive_letter, MakeHasher(), MakeFilter(max_file_size))};
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
