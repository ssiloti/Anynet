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

#ifndef KEY_HPP
#define KEY_HPP

#include <glog/logging.h>

#include "field_utils.hpp"
#include "core.hpp"
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <boost/asio/buffer.hpp>
#include <boost/operators.hpp>
#include <boost/cstdint.hpp>
#include <cstring>
#include <sstream>
#include <iomanip>

using boost::asio::const_buffer;

// A convenient interface to the network hash function (SHA256 as of protocol version 0)
class net_hash
{
public:
	typedef boost::array<boost::uint8_t, SHA256_DIGEST_LENGTH> digest_t;

	net_hash() { ::SHA256_Init(&ctx_); }
	net_hash(const_buffer b)
	{
		::SHA256_Init(&ctx_);
		update(b);
	}

	template <std::size_t N>
	net_hash(const boost::array<boost::uint8_t, N>& d)
	{
		::SHA256_Init(&ctx_);
		update(d);
	}

	operator digest_t() const
	{
		return final();
	}

	template <std::size_t N>
	void update(const boost::array<boost::uint8_t, N>& d)
	{
		::SHA256_Update(&ctx_, d.data(), d.size());
	}

	void update(const digest_t& d)
	{
		::SHA256_Update(&ctx_, d.data(), d.size());
	}

	void update(const std::vector<boost::uint8_t>& d)
	{
		::SHA256_Update(&ctx_, &d[0], d.size());
	}

	void update(const_buffer b)
	{
		::SHA256_Update(&ctx_, buffer_cast<const void*>(b), buffer_size(b));
	}

	digest_t final() const
	{
		digest_t d;
		::SHA256_CTX c(ctx_);
		::SHA256_Final(d.data(), &c);
		return d;
	}

private:
	::SHA256_CTX ctx_;
};

class network_key : boost::totally_ordered<network_key, boost::additive<network_key, boost::additive<network_key, unsigned int> > >
{
	typedef boost::uint64_t intermediate_t;
public:
	const static int packed_size = 32;
	typedef boost::uint32_t digit_t;

	network_key()
	{}

	explicit network_key(ip::tcp::endpoint ep)
	{
		if (ep.address().is_v4()) {
			boost::uint8_t id[ip::address_v4::bytes_type::static_size + 2];
			ip::address_v4::bytes_type bytes(ep.address().to_v4().to_bytes());
			std::memcpy(id, bytes.data(), bytes.size());
			u16(&id[bytes.size()], ep.port());
			SHA256(id, bytes.size() + 2, reinterpret_cast<unsigned char*>(digits_));
		}
		else {
			boost::uint8_t id[ip::address_v6::bytes_type::static_size + 2];
			ip::address_v6::bytes_type bytes(ep.address().to_v6().to_bytes());
			std::memcpy(id, bytes.data(), bytes.size());
			u16(&id[bytes.size()], ep.port());
			SHA256(id, bytes.size() + 2, reinterpret_cast<unsigned char*>(digits_));
		}

		for (int i=0;i<digit_elements;++i)
			digits_[i] = u32(reinterpret_cast<unsigned char*>(&digits_[i]));
	}

	explicit network_key(::X509* cert)
	{
		::X509_pubkey_digest(cert, ::EVP_sha256(), reinterpret_cast<unsigned char*>(digits_), NULL);

		for (int i=0;i<digit_elements;++i)
			digits_[i] = u32(reinterpret_cast<unsigned char*>(&digits_[i]));
	}

	explicit network_key(const_buffer buf)
	{
		hash_of(buf);
	}

	explicit network_key(const boost::uint8_t* buf)
	{
		decode(buf);
	}

	network_key(const net_hash& hash)
	{
		decode(net_hash::digest_t(hash).data());
	}

	explicit network_key(std::istream& strm)
	{
		for (int i=0;i<digit_elements;++i) {
			strm >> digits_[i];
		}
	}

	network_key(std::string s)
	{
		for (int i=0;i<digit_elements;++i) {
			std::stringstream ss(s.substr(i * sizeof(boost::uint32_t) * 2, sizeof(boost::uint32_t) * 2));
			ss >> std::hex >> digits_[i];
		}
	}

	void decode(const boost::uint8_t* buf)
	{
		for (int i=0;i<digit_elements;++i) {
			digits_[i] = u32(buf);
			buf += sizeof(boost::uint32_t);
		}
	}

	boost::uint8_t* encode(boost::uint8_t* p) const
	{
		for (int i=0;i<digit_elements;++i) {
			u32(p, digits_[i]);
			p += sizeof(boost::uint32_t);
		}
		return p;
	}

	bool operator==(const network_key& o) const
	{
		return std::memcmp(digits_, o.digits_, packed_size) == 0;
	}

	bool operator<(const network_key& o) const
	{
		for (int i=0;i<digit_elements;++i)
			if (digits_[i] < o.digits_[i])
				return true;
			else if (digits_[i] > o.digits_[i])
				return false;
		return false;
	}

	network_key& operator-=(const network_key& o)
	{
		// We don't care about underflow here, the result will still be what we wanted
		// For now use the naive solution, it should be fast enough for our needs.
		intermediate_t t = 0;

		for (int i = digit_elements-1; i >= 0; --i) {
			t = intermediate_t(digits_[i]) - o.digits_[i] - t;
			digits_[i] = digit_t(t);
			t >>= 63;
		}
		return *this;
	}

	network_key& operator-=(unsigned int o)
	{
		// We don't care about underflow here, the result will still be what we wanted
		// For now use the naive solution, it should be fast enough for our needs.
		intermediate_t t = o;

		for (int i = digit_elements-1; i >= 0; --i) {
			t = intermediate_t(digits_[i]) - t;
			digits_[i] = digit_t(t);
			t >>= 63;
		}
		return *this;
	}


	network_key& operator+=(const network_key& o)
	{
		// We don't care about overflow here, the result will still be what we wanted
		// For now use the naive solution, it should be fast enough for our needs.
		intermediate_t t = 0;

		for (int i = digit_elements-1; i >= 0; --i) {
			t = intermediate_t(digits_[i]) + o.digits_[i] + t;
			digits_[i] = digit_t(t);
			t >>= 32;
		}
		return *this;
	}

	network_key& operator+=(unsigned int o)
	{
		// We don't care about overflow here, the result will still be what we wanted
		// For now use the naive solution, it should be fast enough for our needs.
		intermediate_t t = o;

		for (int i = digit_elements-1; i >= 0; --i) {
			t = intermediate_t(digits_[i]) + t;
			digits_[i] = digit_t(t);
			t >>= 32;
		}
		return *this;
	}

	network_key& operator/=(digit_t o)
	{
		intermediate_t remainder = 0;

		for (int i=0; i < digit_elements-1; ++i) {
			intermediate_t dividend = (remainder << sizeof(digit_t) * 8) + digits_[i];
			digits_[i] = digit_t(dividend / o);
			remainder = dividend % o;
		}
		return *this;
	}

	network_key operator/(digit_t o)
	{
		network_key t(*this);
		t /= o;
		return t;
	}

	double operator/(const network_key& o)
	{	
		const int double_digits = sizeof(boost::uint64_t) / sizeof(digit_t);

		boost::uint64_t dividend = 0;
		boost::uint64_t divisor = 0;

		int first_digit = digit_elements - 1;
		while (digits_[first_digit] == 0 && o.digits_[first_digit] == 0 && first_digit >= double_digits)
			--first_digit;

		for (int i=0; i < double_digits; ++i)
			dividend |= boost::uint64_t(digits_[i]) << ((double_digits - 1 - i) * sizeof(digit_t) * 8);

		for (int i=0; i < double_digits; ++i)
			divisor |= boost::uint64_t(o.digits_[i]) << ((double_digits - 1 - i) * sizeof(digit_t) * 8);

		// the divisor might be small enough that we truncated it to zero
		// in any case just return 0.0
		if (divisor == 0)
			return 0;

		return double(dividend) / double(divisor);
	}

	void hash_of(const_buffer buf)
	{
		SHA256(buffer_cast<const unsigned char*>(buf), buffer_size(buf), reinterpret_cast<unsigned char*>(digits_));

		for (int i=0;i<digit_elements;++i)
			digits_[i] = u32(reinterpret_cast<unsigned char*>(&digits_[i]));
	}

	network_key& operator=(const boost::uint8_t* buf)
	{
		decode(buf);
		return *this;
	}

	operator std::string() const
	{
		std::stringstream string;
		string << std::hex << std::setw(sizeof(digit_t)*2) << std::setfill('0');
		for (int i=0;i<digit_elements;++i)
			string << digits_[i];
		return string.str();
	}

private:
	static const int digit_elements = packed_size / sizeof(digit_t);
	digit_t digits_[digit_elements];
};

inline network_key distance(const network_key& src, const network_key& dest)
{
	return src - dest;
}

inline network_key reverse_distance(const network_key& src, const network_key& dest)
{
	return dest - src;
}

#endif