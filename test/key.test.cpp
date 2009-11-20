#include "key.hpp"
#include <boost/test/unit_test_suite.hpp>
#include <boost/test/test_tools.hpp>

const unsigned char tn1[] = {0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00,
							 0x00, 0x00, 0x00, 0x00};

const unsigned char tn2[] = {0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00,
							 0x00, 0x00, 0x00, 0x01};

const unsigned char tn3[] = {0xFF, 0xFF, 0xFF, 0xFF,
                             0xFF, 0xFF, 0xFF, 0xFF,
                             0xFF, 0xFF, 0xFF, 0xFF,
                             0xFF, 0xFF, 0xFF, 0xFF,
							 0xFF, 0xFF, 0xFF, 0xFF};

const unsigned char tn4[] = {0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x01,
                             0x00, 0x00, 0x00, 0x00,
							 0x00, 0x00, 0x00, 0x00};

const unsigned char tn5[] = {0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00,
                             0x80, 0x00, 0x00, 0x00,
							 0x00, 0x00, 0x00, 0x00};

const unsigned char tn6[] = {0x35, 0x47, 0x68, 0x64,
                             0x8e, 0x95, 0xca, 0x76,
                             0xf2, 0x7b, 0x52, 0x6f,
                             0xdb, 0xa1, 0x3b, 0xc9,
							 0xfd, 0x26, 0x22, 0x15};

const unsigned char tn7[] = {0xc0, 0xb9, 0x0e, 0x88,
                             0x6e, 0x2e, 0xe2, 0xd1,
                             0x7e, 0x61, 0xec, 0x3e,
                             0x2f, 0x8a, 0x0e, 0xfd,
							 0xa4, 0x03, 0x72, 0x69};

BOOST_AUTO_TEST_CASE(load)
{
	network_key k1(tn1), k2(tn2), k3(tn3);

	BOOST_CHECK(k1 < k2);
	BOOST_CHECK(k3 == k1 - k2);
}

BOOST_AUTO_TEST_CASE(divide)
{
	network_key k1(tn4), k3(tn5);

	network_key k2(k1 / 2);

	BOOST_CHECK(k2 == k3);

	network_key k4(tn6), k5(tn7);

	BOOST_CHECK(k4 / k5 < 1.0);
}