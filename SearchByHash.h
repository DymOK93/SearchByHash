#pragma once
#include <iostream>

void StartSearch(char drive_letter, size_t max_file_size);

template <class Stream, class PathList>
Stream& PrintPathList(Stream& output, char drive_letter, const PathList& list) {
  for (const auto& path : list) {
    output << drive_letter << ":\\" << path << '\n';
  }
  return output;
}


template <class Stream>
Stream& FlushLine(Stream& input) {
  input.clear();
  input.ignore(32767, '\n');
  return input;
}