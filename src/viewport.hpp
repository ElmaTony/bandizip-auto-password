#pragma once
#include <algorithm>
#include <windows.h>
namespace bzap {
inline int ScrollPosition(int position, int content, int page) {
    return std::clamp(position, 0, std::max(0, content - page));
}
inline RECT FitWindow(RECT desired, const RECT &work) {
    int width = std::min(desired.right - desired.left, work.right - work.left);
    int height = std::min(desired.bottom - desired.top, work.bottom - work.top);
    int left = std::clamp(desired.left, work.left, work.right - width);
    int top = std::clamp(desired.top, work.top, work.bottom - height);
    return {left, top, left + width, top + height};
}
} // namespace bzap
