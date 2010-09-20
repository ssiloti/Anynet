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

#include "payload_content_buffer.hpp"
#include "request.hpp"
#include "fragment.hpp"
#include "node.hpp"

using namespace user_content;

void content_request::initiate_request(protocol_id protocol, const content_identifier& key, local_node& node, content_size_t content_size)
{
	last_indirect_request_peer_ = node.id();
	content_size_ = content_size;

	packet::ptr_t pkt(new packet());
	pkt->protocol(protocol);
	pkt->source(node.id());
	pkt->destination(key.publisher);
	pkt->name(key.name);
	pkt->content_status(packet::content_requested);
	pkt->payload(boost::make_shared<payload_request>(content_size_));

	connection::ptr_t con = node.local_request(pkt, key.publisher);

	if (con)
		last_indirect_request_peer_ = con->remote_id() - 1;
}

bool content_request::snoop_packet(local_node& node, packet::ptr_t pkt)
{
	switch (pkt->content_status())
	{
	case packet::content_attached:
		for (std::vector<keyed_handler_t>::iterator handler = handlers_.begin(); handler != handlers_.end(); ++handler)
			(*handler)(pkt->payload_as<payload_content_buffer>()->payload);
		return true;
	case packet::content_detached:
		sources_ = *pkt->payload_as<content_sources::ptr_t>();
		if (!direct_request_pending_) {
			if (!partial_content_) {
				// For now we can't download content which is larger than size_t
				// this would require modifications in the hunk store to do partial mapping
				if (sources_->size > std::numeric_limits<std::size_t>::max()) {
					for (std::vector<keyed_handler_t>::iterator handler = handlers_.begin(); handler != handlers_.end(); ++handler)
						(*handler)(const_payload_buffer_ptr());
					return true;
				}
				partial_content_ = framented_content(static_cast<content_protocol*>(&node.get_protocol(pkt))->get_payload_buffer(std::size_t(sources_->size)));
			}
			std::pair<std::size_t, std::size_t> range = partial_content_->next_invalid_range();
			frame_fragment::ptr_t frag(new frame_fragment(pkt->protocol(), pkt->content_id(), range.first, range.second));
			node.direct_request(sources_->sources.begin()->second.ep, frag);
			++sources_->sources.begin()->second.active_request_count;
			direct_request_pending_ = true;
			direct_request_peer_ = sources_->sources.begin()->first;
		}
		return false;
	case packet::content_failure:
		if (pkt->source() == direct_request_peer_) {
			sources_->sources.erase(direct_request_peer_);
			direct_request_pending_ = false;
		}

		if ( !direct_request_pending_ ) {


			pkt->destination(pkt->source());
			pkt->source(node.id());
			pkt->content_status(packet::content_requested);
			pkt->payload(boost::make_shared<payload_request>(content_size_));

			connection::ptr_t con = node.local_request(pkt, last_indirect_request_peer_);

			if (con) {
				DLOG(INFO) << "Retrying content_request for " << std::string(pkt->destination()) << " to " << std::string(con->remote_id()) << " with inner id " << std::string(last_indirect_request_peer_);
				last_indirect_request_peer_ = con->remote_id() - 1;
				return false;
			}
			else {
				google::FlushLogFiles(google::INFO);
				for (std::vector<keyed_handler_t>::iterator handler = handlers_.begin(); handler != handlers_.end(); ++handler)
					(*handler)(const_payload_buffer_ptr());
				return true;
			}
		}
		else {
			return false;
		}
	default:
		return false;
	}
}

const_payload_buffer_ptr content_request::snoop_fragment(local_node& node, const network_key& src, frame_fragment::ptr_t frag)
{
	if (!partial_content_) {
		// We got a fragment frame for something we haven't started a fragmented download on yet
		// just ignore it
		frag->to_request(0, 0);
		return const_payload_buffer_ptr();
	}

	content_sources::sources_t::iterator content_source = sources_->sources.find(src);

	direct_request_pending_ = false;
	--content_source->second.active_request_count;

	switch (frag->status())
	{
	case frame_fragment::status_attached:
		{
			partial_content_->mark_valid(frag, content_source->second.ep.address());

			const_payload_buffer_ptr payload = partial_content_->complete();

			if (payload) {
				if (static_cast<content_protocol*>(&node.get_protocol(frag->protocol()))->content_id(payload) == frag->id())
					return payload;
				else
					partial_content_->reset();
			}
			break;
		}
	case frame_fragment::status_failed:
		if (sources_) {
			sources_->sources.erase(content_source);
			if (!sources_->sources.empty()) {
				content_source = sources_->sources.begin();
			}
			else
				return const_payload_buffer_ptr();
		}
		break;
	}

	std::pair<std::size_t, std::size_t> next_range(partial_content_->next_invalid_range());
	frag->to_request(next_range.first, next_range.second);
	node.direct_request(content_source->second.ep, frag);
	++content_source->second.active_request_count;
	direct_request_pending_ = true;
	direct_request_peer_ = content_source->first;

	return const_payload_buffer_ptr();
}

framented_content::fragment_buffer content_request::get_fragment_buffer(std::size_t offset, std::size_t size)
{
	if (partial_content_)
		return partial_content_->get_fragment_buffer(offset, size);
	else
		return framented_content::fragment_buffer(offset);
}

bool content_request::timeout(local_node& node, packet::ptr_t pkt)
{
	if (direct_request_pending_) {
		frame_fragment::ptr_t frag(new frame_fragment(pkt->protocol()));
		snoop_fragment(node, direct_request_peer_, frag);
		if (frag->status() != frame_fragment::status_failed)
			return false;
	}

	return snoop_packet(node, pkt);
}

