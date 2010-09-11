#include "hunk.hpp"
#include <boost/test/unit_test_suite.hpp>
#include <boost/test/test_tools.hpp>

#define NODE_HPP

class local_node
{
public:

//	hunk_descriptor_t cache_local_request(signature_scheme_id pid, content_identifier id, std::size_t size);
//	hunk_descriptor_t cache_store(signature_scheme_id pid, content_identifier id, std::size_t size);
//	hunk_descriptor_t cache_remote_request(signature_scheme_id pid, content_identifier id, std::size_t size, boost::posix_time::time_duration request_delta);
	hunk_descriptor_t load_existing_hunk(signature_scheme_id pid, content_identifier id, std::size_t size)
	{
		stored_hunks_.push_back(stored_hunk(pid, id, size, 0, false));
		return --stored_hunks_.end();
	}

//	hunk_descriptor_t not_a_hunk() { return stored_hunks_.end(); }

	stored_hunks_t stored_hunks_;
};

#include "hunk.cpp"

BOOST_AUTO_TEST_CASE(store)
{
	content_identifier cid;
	std::vector<boost::uint8_t> comp;
	comp.push_back('t');
	comp.push_back('s');
	comp.push_back('t');
	cid.name.add_component(comp);
	comp.push_back('2');
	cid.name.add_component(comp);

	{
		local_node node;
		content_store store("./test", 0, node);
		std::string foo("foo");
		//store.put(network_key(), buffer(foo));
		mapped_content::ptr temp_content = store.get_temp(foo.length());
		hunk_descriptor_t temp_desc = node.load_existing_hunk(0, cid, foo.length());
		std::memcpy(buffer_cast<unsigned char*>(temp_content->get()), foo.data(), foo.length());
		store.put(temp_desc, temp_content);
	//	const_payload_buffer_ptr foo_content = store.get(content_identifier());
	//	store.unlink(content_identifier());
	}

	{
		local_node node;
		content_store store("./test", 0, node);
		std::string foo("foo");
		//store.put(network_key(), buffer(foo));
		const_payload_buffer_ptr foo_content = store.get(cid);
		BOOST_CHECK(foo_content != const_payload_buffer_ptr());
		store.unlink(cid);
	}
}
