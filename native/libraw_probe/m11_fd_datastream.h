#pragma once

#include <libraw/libraw_datastream.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace m11raw {

/**
 * LibRaw datastream backed by an owned duplicate of an Android/Posix fd.
 *
 * Android ACTION_OPEN_DOCUMENT supplies a ParcelFileDescriptor rather than a
 * stable path.  Duplicating the fd here lets Java close its wrapper while the
 * native LibRaw decode owns a seekable descriptor.  Reads use pread(), so there
 * is no full-file Java/native staging copy.
 */
class FdDatastream final : public LibRaw_abstract_datastream {
public:
    explicit FdDatastream(int source_fd) : fd_(-1), pos_(0), size_(0) {
        if (source_fd < 0) return;
        fd_ = ::dup(source_fd);
        if (fd_ < 0) return;
        struct stat st {};
        if (::fstat(fd_, &st) != 0 || st.st_size < 0) {
            ::close(fd_);
            fd_ = -1;
            return;
        }
        size_ = static_cast<INT64>(st.st_size);
    }

    ~FdDatastream() override {
        if (fd_ >= 0) ::close(fd_);
    }

    FdDatastream(const FdDatastream &) = delete;
    FdDatastream &operator=(const FdDatastream &) = delete;

    int valid() override {
        std::lock_guard<std::recursive_mutex> guard(mu_);
        return fd_ >= 0 ? 1 : 0;
    }

    int read(void *ptr, size_t item_size, size_t item_count) override {
        std::lock_guard<std::recursive_mutex> guard(mu_);
        if (fd_ < 0 || ptr == nullptr || item_size == 0 || item_count == 0) return 0;
        if (item_count > std::numeric_limits<size_t>::max() / item_size) return 0;
        const size_t wanted = item_size * item_count;
        size_t total = 0;
        auto *dst = static_cast<unsigned char *>(ptr);
        while (total < wanted) {
            ssize_t n = ::pread(fd_, dst + total, wanted - total,
                                static_cast<off_t>(pos_ + static_cast<INT64>(total)));
            if (n < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (n == 0) break;
            total += static_cast<size_t>(n);
        }
        pos_ += static_cast<INT64>(total);
        return static_cast<int>(total / item_size);
    }

    int seek(INT64 offset, int whence) override {
        std::lock_guard<std::recursive_mutex> guard(mu_);
        if (fd_ < 0) return 1;
        INT64 base = 0;
        switch (whence) {
            case SEEK_SET: base = 0; break;
            case SEEK_CUR: base = pos_; break;
            case SEEK_END: base = size_; break;
            default: return 1;
        }
        if ((offset > 0 && base > std::numeric_limits<INT64>::max() - offset) ||
            (offset < 0 && base < std::numeric_limits<INT64>::min() - offset)) {
            return 1;
        }
        const INT64 target = base + offset;
        if (target < 0) return 1;
        pos_ = target;
        return 0;
    }

    INT64 tell() override {
        std::lock_guard<std::recursive_mutex> guard(mu_);
        return pos_;
    }

    INT64 size() override {
        std::lock_guard<std::recursive_mutex> guard(mu_);
        return size_;
    }

    int get_char() override {
        unsigned char value = 0;
        return read(&value, 1, 1) == 1 ? static_cast<int>(value) : EOF;
    }

    char *gets(char *dst, int capacity) override {
        std::lock_guard<std::recursive_mutex> guard(mu_);
        if (fd_ < 0 || dst == nullptr || capacity < 1) return nullptr;
        int written = 0;
        bool saw_any = false;
        while (written < capacity - 1) {
            unsigned char ch = 0;
            if (read(&ch, 1, 1) != 1) break;
            saw_any = true;
            if (ch == '\n') break; // std::istream::getline-style delimiter removal
            dst[written++] = static_cast<char>(ch);
        }
        dst[written] = '\0';
        return saw_any ? dst : nullptr;
    }

    int scanf_one(const char *fmt, void *value) override {
        std::lock_guard<std::recursive_mutex> guard(mu_);
        if (fd_ < 0 || fmt == nullptr || value == nullptr) return EOF;
        if (std::strcmp(fmt, "%d") != 0 && std::strcmp(fmt, "%f") != 0) return EOF;

        std::string token;
        int ch;
        do {
            ch = get_char();
            if (ch == EOF) return EOF;
        } while (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n');

        while (ch != EOF && ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
            if (token.size() >= 127) return EOF;
            token.push_back(static_cast<char>(ch));
            ch = get_char();
        }
        if (ch != EOF) seek(-1, SEEK_CUR); // leave delimiter for std-stream-like behavior
        if (token.empty()) return EOF;

        char *end = nullptr;
        errno = 0;
        if (std::strcmp(fmt, "%d") == 0) {
            long parsed = std::strtol(token.c_str(), &end, 10);
            if (errno || end == token.c_str() || *end != '\0' ||
                parsed < std::numeric_limits<int>::min() || parsed > std::numeric_limits<int>::max()) {
                return EOF;
            }
            *static_cast<int *>(value) = static_cast<int>(parsed);
        } else {
            float parsed = std::strtof(token.c_str(), &end);
            if (errno || end == token.c_str() || *end != '\0') return EOF;
            *static_cast<float *>(value) = parsed;
        }
        return 1;
    }

    int eof() override {
        std::lock_guard<std::recursive_mutex> guard(mu_);
        return (fd_ < 0 || pos_ >= size_) ? 1 : 0;
    }

    int lock() override {
        mu_.lock();
        return 1;
    }

    void unlock() override { mu_.unlock(); }

    const char *fname() override { return nullptr; }

private:
    int fd_;
    INT64 pos_;
    INT64 size_;
    std::recursive_mutex mu_;
};

} // namespace m11raw
