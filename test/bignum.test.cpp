#include "bignum.hpp"
#include <boost/test/unit_test_suite.hpp>
#include <boost/test/test_tools.hpp>
#include <algorithm>

const unsigned char bignum_bin[] = {0x01, 0x01};

BOOST_AUTO_TEST_CASE(decode_encode)
{
	unsigned char encoded_bin[sizeof(bignum_bin)];
	openssl::bignum bn(boost::asio::buffer(bignum_bin, sizeof(bignum_bin)));
	bn.encode(boost::asio::buffer(encoded_bin, sizeof(bignum_bin)));
	BOOST_CHECK(std::equal(bignum_bin, bignum_bin + sizeof(bignum_bin), encoded_bin));
}