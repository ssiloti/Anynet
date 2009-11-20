#include "hunk.hpp"
#include <boost/test/unit_test_suite.hpp>
#include <boost/test/test_tools.hpp>

BOOST_AUTO_TEST_CASE(store)
{
	content_store store;
	std::string foo("foo");
	//store.put(network_key(), buffer(foo));
	content_store::mapped_content_ptr temp_content = store.get_temp(foo.length());
	std::memcpy(buffer_cast<unsigned char*>(temp_content->get()), foo.data(), foo.length());
	store.put(network_key(), temp_content);
	content_store::const_mapped_content_ptr foo_content = store.get(network_key());
	store.unlink(store.stat(network_key()));
}