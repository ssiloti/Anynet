#ifndef RSA_AUTHORITY_HPP
#define RSA_AUTHORITY_HPP

#include "core.hpp"
#include <openssl/rsa.h>
#include <boost/serialization/split_member.hpp>
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

private:
	friend class authority;
	friend class boost::serialization::access;

	RSA* key_;

	template<class Archive>
    void save(Archive & ar, const unsigned int version)
	{
		std::vector<unsigned char> buf(i2d_RSAPrivateKey(key_, NULL));
		unsigned char* buf_ptr = &buf[0];
		i2d_RSAPrivateKey(key_, &buf_ptr);
		ar & buf;
	}

	template<class Archive>
    void load(Archive & ar, const unsigned int version)
	{
		std::vector<unsigned char> buf;
		ar & buf;
		unsigned char* buf_ptr = &buf[0];
		key_ = d2i_RSAPrivateKey(&key_, &buf_ptr, buf.size());
	}

	BOOST_SERIALIZATION_SPLIT_MEMBER()
};

class authority
{
public:
	explicit authority() : key_(NULL) {}
	authority(const_buffer key);
	authority(const author& auth) : key_(RSAPublicKey_dup(auth.key_)) {}

	bool verify(const_buffer message, const_buffer signature) const;

private:
	friend class boost::serialization::access;

	RSA* key_;

	template<class Archive>
    void save(Archive & ar, const unsigned int version)
	{
		std::vector<unsigned char> buf(i2d_RSAPublicKey(key_, NULL));
		unsigned char* buf_ptr = &buf[0];
		i2d_RSAPublicKey(key_, &buf_ptr);
		ar & buf;
	}

	template<class Archive>
    void load(Archive & ar, const unsigned int version)
	{
		std::vector<unsigned char> buf;
		ar & buf;
		unsigned char* buf_ptr = &buf[0];
		key_ = d2i_RSAPublicKey(&key_, &buf_ptr, buf.size());
	}

	BOOST_SERIALIZATION_SPLIT_MEMBER()
};

#endif
