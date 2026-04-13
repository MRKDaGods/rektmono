#pragma once

#include <type_traits>

namespace mrk::traits {

	/// Type traits to detect string types
	template<typename T>
	struct is_string : std::false_type {};

	template<> struct is_string<const char*> : std::true_type {};
	template<> struct is_string<char*> : std::true_type {};
	template<size_t N> struct is_string<const char[N]> : std::true_type {};
	template<size_t N> struct is_string<char[N]> : std::true_type {};
	template<> struct is_string<const wchar_t*> : std::true_type {};
	template<> struct is_string<wchar_t*> : std::true_type {};
	template<size_t N> struct is_string<const wchar_t[N]> : std::true_type {};
	template<size_t N> struct is_string<wchar_t[N]> : std::true_type {};

	template<typename T>
	constexpr bool is_string_v = is_string<std::decay_t<T>>::value;

}