// anynet
// Copyright (C) 2009  Steven Siloti
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//
// In addition, as a special exception, the copyright holders give
// permission to link the code of portions of this program with the
// OpenSSL library under certain conditions as described in each
// individual source file, and distribute linked combinations
// including the two.
//
// You must obey the GNU General Public License in all respects
// for all of the code used other than OpenSSL.  If you modify
// file(s) with this exception, you may extend this exception to your
// version of the file(s), but you are not obligated to do so.  If you
// do not wish to do so, delete this exception statement from your
// version.  If you delete this exception statement from all source
// files in the program, then also delete it here.
//
// Contact:  Steven Siloti <ssiloti@gmail.com>

#ifndef FIELD_UTILS_HPP
#define FIELD_UTILS_HPP

#include <boost/cstdint.hpp>

inline boost::uint16_t u16(const boost::uint8_t b[2]) { return b[0] << 8 | b[1]; }

inline boost::uint32_t u32(const boost::uint8_t b[4]) { return b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]; }

inline void u16(boost::uint8_t b[2], boost::uint16_t i) { b[0] = i >> 8; b[1] = i & 0xFF; }

inline void u32(boost::uint8_t b[4], boost::uint32_t i) { b[0] = i >> 24; b[1] = i >> 16 & 0xFF; b[2] = i >> 8 & 0xFF; b[3] = i & 0xFF; }

template <int Bn, typename I>
bool bit(I b) { return (b & 1 << Bn) != 0; }

template <int Bn, typename I>
void bit(I& b, bool bit) { b = b & ~(1 << Bn) | (bit << Bn); }

#endif
