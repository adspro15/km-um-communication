#pragma once

#ifndef sprintf
/***/#define sprintf sprintf_
#endif
int sprintf_(char* buffer, const char* format, ...);

#ifndef snprintf
/***/#define snprintf  snprintf_
#endif
int  snprintf_(char* buffer, size_t count, const char* format, ...);

#ifndef vsnprintf
/***/#define vsnprintf vsnprintf_
#endif
int vsnprintf_(char* buffer, size_t count, const char* format, va_list va);