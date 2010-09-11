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

#ifndef PROTOCOL_NON_AUTHORITATIVE_HPP
#define PROTOCOL_NON_AUTHORITATIVE_HPP

#include <glog/logging.h>

#include "hunk.hpp"
#include "signature_schemes/user_content.hpp"
#include "key.hpp"
#include "node.hpp"
#include <boost/smart_ptr.hpp>
#include <map>

#ifdef SIMULATION
#include "simulator.hpp"
#endif

class non_authoritative : public user_content
{
public:
	static const signature_scheme_id protocol_id = signature_sha256;

	struct insert_buffer : public mutable_shared_buffer
	{
		friend class non_authoritative;

		insert_buffer(mapped_content::ptr b);

		void chunk_size(std::size_t s);
		std::size_t chunk_size() const;

		virtual mutable_buffer get();
		virtual const_buffer get() const;

	private:
		mapped_content::ptr backing;
	};

	static void create(local_node& node)
	{
		boost::shared_ptr<non_authoritative> ptr(new non_authoritative(node));
		ptr->register_handler();
		ptr->start_vacume();
	}

	insert_buffer get_insertion_buffer(std::size_t size);
	content_identifier insert_hunk(insert_buffer hunk);

	template <typename Handler>
	void retrieve_hunk(const content_identifier& key, Handler handler)
	{
		new_content_request(key, 0, boost::bind(&non_authoritative::hunk_retrieved<Handler>, handler, _1));
	}

	virtual const_payload_buffer_ptr get_content(const content_identifier& key);
	virtual void store_content(hunk_descriptor_t desc, const_payload_buffer_ptr content);
	virtual content_identifier content_id(const_payload_buffer_ptr content);

	virtual payload_buffer_ptr get_payload_buffer(std::size_t size)
	{
		return stored_hunks_.get_temp(size);
	}

	virtual void prune_hunk(const content_identifier& id)
	{
		stored_hunks_.unlink(content_identifier(id));
	}

	~non_authoritative()
	{
#ifdef SIMULATION
//		assert(!sim.node_created(node_id));
		for (content_store::const_iterator hunk = stored_hunks_.begin(); hunk != stored_hunks_.end(); ) {
			content_identifier hid = hunk->first;
			++hunk;
			stored_hunks_.unlink(hid);
		}
#endif
	}

private:

	non_authoritative(local_node& node);

	template <typename Handler>
	static void hunk_retrieved(Handler handler, const_payload_buffer_ptr content)
	{
		if (!content) {
			DLOG(INFO) << ": Failed to retrieve hunk :(";
			handler(const_payload_buffer_ptr());
			return;
		}

		handler(content);
	}

	content_store stored_hunks_;
};

#endif