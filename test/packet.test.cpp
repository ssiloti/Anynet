#include "../packet.cpp"
#include <boost/test/unit_test_suite.hpp>
#include <boost/test/test_tools.hpp>
#include <algorithm>

const boost::uint8_t address_bin[] = {0x55, 0x55, 0x55, 0x55,
                                      0x55, 0x55, 0x55, 0x55,
                                      0x55, 0x55, 0x55, 0x55,
                                      0x55, 0x55, 0x55, 0x55,
                                      0x55, 0x55, 0x55, 0x55,
                                      0x44, 0x44, 0x44, 0x44,
                                      0x22, 0x22, 0x03, 0x00};

const boost::uint8_t packet_bin[] = {0x00, 0x01, 0x00, 0x01,
                                     0x00, 0x00, 0x00, 0x04,
                                     0x01, 0x23, 0x45, 0x67,
                                     0x89, 0x01, 0x23, 0x45,
                                     0x67, 0x89, 0x01, 0x23,
                                     0x45, 0x67, 0x89, 0x01,
                                     0x23, 0x45, 0x67, 0x89,
                                     0x3F, 0x00, 0x00, 0x01,
                                     0x40, 0x41, 0x40, 0x00,
                                     0x01, 0x23, 0x45, 0x67,
                                     0x89, 0x01, 0x23, 0x45,
                                     0x67, 0x89, 0x01, 0x23,
                                     0x45, 0x67, 0x89, 0x01,
                                     0x23, 0x45, 0x67, 0x89,
                                     0x3F, 0x00, 0x00, 0x01,
                                     0x41, 0x42, 0x40, 0x00,
                                     0xFF, 0xFF, 0xFF, 0xFF};

/*BOOST_AUTO_TEST_CASE(address_decode_encode)
{
	address adr = address(address_bin);
	BOOST_CHECK_EQUAL(adr.oob_threshold(), 3);

	boost::uint8_t encoded_buf[sizeof(address_bin)];
	adr.encode(encoded_buf);
	BOOST_CHECK(std::equal(address_bin, address_bin + sizeof(address_bin), encoded_buf));
}*/

BOOST_AUTO_TEST_CASE(packet_decode)
{
	packet pkt;
	const boost::uint8_t* p = packet_bin;

	int destinations = packet_do_parse_header<address_traits_v4>(pkt, packet_bin);;

	BOOST_CHECK_EQUAL(destinations, 1);
	BOOST_CHECK_EQUAL(pkt.protocol(), 1);
	BOOST_CHECK_EQUAL(pkt.drop_crumbs(), false);
	BOOST_CHECK_EQUAL(buffer_size(pkt.payload()->get()), 4);
	BOOST_CHECK_EQUAL(pkt.source().oob_endpoint().port(), 0x4041);

	boost::uint8_t dest_buffer[sizeof(packet_bin) - 36];
	std::memcpy(dest_buffer, packet_bin + 36, sizeof(dest_buffer));
	int remainder = packet_do_parse_desinations<address_traits_v4>(pkt, mutable_buffer(dest_buffer, sizeof(dest_buffer)), destinations);

	BOOST_CHECK_EQUAL(destinations, 0);
	BOOST_CHECK_EQUAL(pkt.destinations().size(), 1);
	BOOST_CHECK_EQUAL(pkt.destinations().begin()->oob_endpoint().port(), 0x4142);
	BOOST_CHECK_EQUAL(remainder, 4);
}