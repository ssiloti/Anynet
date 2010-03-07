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

#include "protocols/non_authoritative.hpp"
#include "node.hpp"

non_authoritative::non_authoritative(local_node& node)
	: user_content(node, protocol_id), stored_hunks_(node.config().content_store_path() + "/non_authoritative", protocol_id, node)
{
}

const_payload_buffer_ptr non_authoritative::get_content(const network_key& key)
{
	return stored_hunks_.get(key);
}

network_key non_authoritative::content_id(const_payload_buffer_ptr content)
{
	return network_key(content->get());
}

void non_authoritative::store_content(hunk_descriptor_t desc, const_payload_buffer_ptr content)
{
	stored_hunks_.put(desc, std::vector<const_buffer>(1, content->get()));

#ifdef SIMULATION
	sim.stored_non_authoritative_hunk(desc->id);
#endif
}

void non_authoritative::insert_hunk(const_payload_buffer_ptr hunk)
{
	new_content_store(hunk);
}
