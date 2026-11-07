#pragma once
#include "ark_abi.hpp"
#include <cstddef>
#include <string>
namespace bzap {
struct Result {
    std::wstring archive;
    std::wstring outcome; // success, passwords_exhausted, password_or_data_error, error, canceled
    ark::Error error = 0;
    std::size_t attempts = 0, savedCount = 0, completedFiles = 0;
    bool opening = false;
};
void RecordResult(const Result &result, bool notify);
void OperationStarted();
void OperationFinished();
void FinishNotifications();
void ShowRecords();
} // namespace bzap
