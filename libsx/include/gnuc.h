/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef GNUC_H
#define GNUC_H

#ifdef __GNUC__
#define FMT_PRINTF(idxfmt, idxva) __attribute__((format(printf, idxfmt, idxva)))
#define NORETURN  __attribute__((__noreturn__))

#if __GNUC__ >= 4

#if __GNUC_MINOR__ >= 5 && !defined(_GLIBCXX_DEBUG)
#define UNREACHABLE __builtin_unreachable()
#endif
#if __GNUC_MINOR__ >= 3
#define COLD __attribute__((cold))
#else
#define COLD
#endif
#define LIKELY(e) __builtin_expect(!!(e), 1)
#define UNLIKELY(e) __builtin_expect(!!(e), 0)

#else

#define COLD
#define LIKELY(e) (e)
#define UNLIKELY(e) (e)
#endif

#ifndef UNREACHABLE
#define UNREACHABLE unreachable()
#endif

#else
#define FMT_PRINTF(idxfmt, idxva)
#define COLD
#define NORETURN
#define LIKELY(e) (e)
#define UNLIKELY(e) (e)
#endif

#ifdef __cplusplus

#ifdef __GNUC__
#define PRETTYFUNC __PRETTY_FUNCTION__
#define FUNC __func__
#else
#define PRETTYFUNC ""
#define FUNC ""
#endif

#endif

void unreachable(void) NORETURN;
#endif
