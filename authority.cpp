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

#include "authority.hpp"
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <boost/filesystem/operations.hpp>

authority::authority(const_buffer key) : key_(NULL)
{
	const unsigned char* buf_ptr = buffer_cast<const unsigned char*>(key);
	key_ = d2i_RSAPublicKey(&key_, &buf_ptr, buffer_size(key));
}

authority::~authority()
{
	RSA_free(key_);
}

bool authority::verify(const_buffer message, const_buffer signature) const
{
	return RSA_verify(NID_sha1,
	                  buffer_cast<const unsigned char*>(message),
	                  buffer_size(message),
	                  buffer_cast<const unsigned char*>(signature),
	                  buffer_size(signature),
	                  key_);
}

author::author(const std::string& cert_file)
	: key_(NULL)
{
	if (!boost::filesystem::exists(cert_file)) {
		::EVP_PKEY* pk = ::EVP_PKEY_new();
		::X509* x = ::X509_new();
		key_ = ::RSA_generate_key(2048, RSA_F4, NULL, NULL);

		::EVP_PKEY_assign_RSA(pk, key_);

		::X509_set_version(x, 2);
		::ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
		::ASN1_UTCTIME_set_string(X509_get_notBefore(x), "000101000000Z");
		::ASN1_GENERALIZEDTIME_set_string(X509_get_notAfter(x), "99991231235959Z");
		::X509_set_pubkey(x, pk);

		::X509_NAME* name = ::X509_get_subject_name(x);

		::X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"anynet/0", -1, -1, 0);
		::X509_set_issuer_name(x,name);

		::X509_sign(x,pk,::EVP_md5());

		std::FILE* fp = std::fopen(cert_file.c_str(), "w");
		::PEM_write_X509(fp, x);
		::PEM_write_PrivateKey(fp, pk, NULL, NULL, 0, NULL, NULL);
		std::fclose(fp);

		::X509_free(x);
		::EVP_PKEY_free(pk);
	}
	else {
		std::FILE* fp = std::fopen(cert_file.c_str(), "r");
		::PEM_read_RSAPrivateKey(fp, &key_, NULL, NULL);
		std::fclose(fp);
	}
}

mutable_buffer author::sign(const_buffer message, mutable_buffer signature) const
{
	unsigned int sig_size;
	RSA_sign(NID_sha1,
	         buffer_cast<const unsigned char*>(message),
	         buffer_size(message),
	         buffer_cast<unsigned char*>(signature),
	         &sig_size,
	         key_);
	return buffer(signature, sig_size);
}