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

#include "protocols/user_content/non_authoritative.hpp"
#include "node.hpp"
#include <boost/make_shared.hpp>

namespace
{
	struct packed_content
	{
		boost::uint8_t chunk_size;
		boost::uint8_t rsvd[3];
		boost::uint8_t content[];
	};
}

void non_authoritative::create(boost::shared_ptr<local_node> node, boost::shared_ptr<transport::trivial> t)
{
	boost::shared_ptr<non_authoritative> ptr(boost::make_shared<non_authoritative>(boost::ref(node), t));
	ptr->register_handler();
	ptr->start_vacume();
	ptr->transport_->register_upper_layer(ptr->id(), ptr);
}

non_authoritative::insert_buffer::insert_buffer(mapped_content::ptr b)
	: backing(b)
{
	packed_content* c(buffer_cast<packed_content*>(backing->get()));
	c->chunk_size = c->rsvd[0] = c->rsvd[1] = c->rsvd[2] = 0;
}

void non_authoritative::insert_buffer::chunk_size(std::size_t s)
{
	buffer_cast<packed_content*>(backing->get())->chunk_size = s;
}

std::size_t non_authoritative::insert_buffer::chunk_size() const
{
	return buffer_cast<const packed_content*>(backing->get())->chunk_size;
}

mutable_buffer non_authoritative::insert_buffer::get()
{
	return backing->get() + sizeof(packed_content);
}

const_buffer non_authoritative::insert_buffer::get() const
{
	return backing->get() + sizeof(packed_content);
}

non_authoritative::non_authoritative(boost::shared_ptr<local_node> node, boost::shared_ptr<transport::trivial> t)
	: user_content::content_protocol(node, protocol_id, t->public_endpoint())
	, stored_hunks_(node->config().content_store_path() + "/non_authoritative", protocol_id, *node)
	, transport_(t)
{}

non_authoritative::insert_buffer non_authoritative::get_insertion_buffer(std::size_t size)
{
	return stored_hunks_.get_temp(size + sizeof(packed_content));
}

content_identifier non_authoritative::insert_hunk(insert_buffer hunk)
{
	content_identifier cid(content_id(hunk.backing->get()));
	// Since the user is requesting an insertion while providing just a buffer, we need to make sure the
	// content gets inserted into the local store so we can serve it up to requesters
	hunk_descriptor_t hunk_desc = node_->cache_local_request(id(), cid, buffer_size(hunk.backing->get()));
	if (hunk_desc != node_->not_a_hunk())
		store_content(hunk_desc, hunk.backing);
	new_content_store(cid, hunk.backing);
	return cid;
}

const_payload_buffer_ptr non_authoritative::get_content(const content_identifier& key)
{
	return stored_hunks_.get(key);
}

content_identifier non_authoritative::content_id(const_buffer content)
{
	const packed_content* c = buffer_cast<const packed_content*>(content);

	if (c->chunk_size >= sizeof(std::size_t))
		throw bad_content();

	std::size_t chunk_size = c->chunk_size & sizeof(std::size_t) * 8 - 1;
	if (chunk_size == 0)
		chunk_size = std::numeric_limits<std::size_t>::max();
	else
		chunk_size = 1 << chunk_size;

	std::size_t content_size = buffer_size(content) - sizeof(packed_content);
	chunk_size = std::min(chunk_size, content_size);
	const boost::uint8_t* end_of_content = c->content + content_size;

	net_hash root_hash;
	for (const boost::uint8_t* chunk = c->content; chunk < end_of_content ; chunk += chunk_size)
		root_hash.update(net_hash(const_buffer(chunk, std::min(chunk_size, size_t(end_of_content - chunk)))));

	return content_identifier(network_key(root_hash));
}

void non_authoritative::start_direct_request(const content_identifier& cid, boost::shared_ptr<content_sources> sources)
{
	transport_->start_request(id(), cid, sources);
}

void non_authoritative::stop_direct_request(const content_identifier& cid)
{
	transport_->stop_request(id(), cid);
}

void non_authoritative::store_content(hunk_descriptor_t desc, const_payload_buffer_ptr content)
{
	stored_hunks_.put(desc, std::vector<const_buffer>(1, content->get()));

#ifdef SIMULATION
	sim.stored_non_authoritative_hunk(desc->id.publisher);
#endif
}
