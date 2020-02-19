//
// Created by ISU on 09/02/2020.
//

#ifndef CRYPTOBENCH_SECURE_STRING_HPP
#define CRYPTOBENCH_SECURE_STRING_HPP

#include <string>

/// source: https://codereview.stackexchange.com/questions/107991/hacking-a-securestring-based-on-stdbasic-string-for-c

namespace security
{
    inline void SecureZeroMemory(void *p, std::size_t n)
    {
        std::fill_n(static_cast<volatile char*>(p), n, 0);
    }

    template<typename T>
    struct allocator
    {
        using value_type = T;
        using propagate_on_container_move_assignment =
                typename std::allocator_traits<std::allocator<T>>
                ::propagate_on_container_move_assignment;

        constexpr allocator() = default;
        constexpr allocator(const allocator&) = default;
        template <class U> constexpr allocator(const allocator<U>&) noexcept {}

        static T* allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }
        static void deallocate(T* p, std::size_t n) noexcept
        {
            SecureZeroMemory(p, n * sizeof *p);
            std::allocator<T>{}.deallocate(p, n);
        }
    };

    template<typename T, typename U>
    constexpr bool operator==(const allocator<T> &, const allocator<U> &) noexcept
    {
        return true;
    }

    template<typename T, typename U>
    constexpr bool operator!=(const allocator<T> &, const allocator<U> &) noexcept
    {
        return false;
    }

    using secure_string = std::string;//std::basic_string<char, std::char_traits<char>, allocator<char>>;
}

/*namespace std
{
    template <>
    inline security::secure_string::~basic_string()
    {
        using X = std::basic_string<char, std::char_traits<char>
        , security::allocator<unsigned char>>;

        ((X*)this)->~X();
        ::security::SecureZeroMemory(this, sizeof *this);
    }
}*/

#endif //CRYPTOBENCH_SECURE_STRING_HPP
