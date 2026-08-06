#pragma once

#include <variant>
#include <string>
#include <utility>
#include <stdexcept>

namespace atlas::packet {

template <typename T, typename E = std::string>
class Result {
    std::variant<T, E> value_;

public:
    Result(T t) : value_(std::move(t)) {}
    Result(E e) : value_(std::move(e)) {}

    [[nodiscard]] bool ok() const noexcept {
        return std::holds_alternative<T>(value_);
    }

    explicit operator bool() const noexcept {
        return ok();
    }

    T& get() {
        if (!ok()) {
            throw std::logic_error("Attempted to call get() on an error Result");
        }
        return std::get<T>(value_);
    }

    const T& get() const {
        if (!ok()) {
            throw std::logic_error("Attempted to call get() on an error Result");
        }
        return std::get<T>(value_);
    }

    E& error() {
        if (ok()) {
            throw std::logic_error("Attempted to call error() on a successful Result");
        }
        return std::get<E>(value_);
    }

    const E& error() const {
        if (ok()) {
            throw std::logic_error("Attempted to call error() on a successful Result");
        }
        return std::get<E>(value_);
    }
};

} // namespace atlas::packet
