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

#ifndef AUTHORITY_HPP
#define AUTHORITY_HPP

#include <glog/logging.h>

#include "core.hpp"
#include <openssl/rsa.h>
#include <string>

enum signature_scheme
{
	rsassa_pkcs1v15_sha = 0
};

class author
{
public:
	author() : key_(NULL) {}
	explicit author(unsigned int bits);

	boost::uint16_t signature_length() { return boost::uint16_t(RSA_size(key_)); }
	mutable_buffer sign(const_buffer message, mutable_buffer signature) const;

	int serialize(mutable_buffer buf)
	{
		unsigned char* ptr = buffer_cast<unsigned char*>(buf);
		return i2d_RSAPrivateKey(key_, &ptr);
	}

	int serialize()
	{
		return i2d_RSAPrivateKey(key_, NULL);
	}

	void parse(const_buffer buf)
	{
		const unsigned char* ptr = buffer_cast<const unsigned char*>(buf);
		d2i_RSAPrivateKey(&key_, &ptr, buffer_size(buf));
	}

private:
	friend class authority;

	RSA* key_;
};

class authority
{
public:
	authority() : key_(NULL) {}
	authority(const_buffer key);
	authority(const author& auth) : key_(RSAPublicKey_dup(auth.key_)) {}
	~authority();

	bool verify(const_buffer message, const_buffer signature) const;

	int serialize(mutable_buffer buf)
	{
		unsigned char* ptr = buffer_cast<unsigned char*>(buf);
		return i2d_RSAPublicKey(key_, &ptr);
	}

	int serialize()
	{
		return i2d_RSAPublicKey(key_, NULL);
	}

	void parse(const_buffer buf)
	{
		const unsigned char* ptr = buffer_cast<const unsigned char*>(buf);
		d2i_RSAPublicKey(&key_, &ptr, buffer_size(buf));
	}

private:

	RSA* key_;
};

#endif