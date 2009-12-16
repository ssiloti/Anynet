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

#ifndef HUNK_HPP
#define HUNK_HPP

#include <glog/logging.h>

#include "core.hpp"
#include "key.hpp"
#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/smart_ptr.hpp>
#include <boost/filesystem.hpp>
#include <cstdio>

#ifdef BOOST_WINDOWS
#include <Windows.h>
#else
#include <sys/types.h>
#endif

using namespace boost::interprocess;

class local_node;

struct stored_hunk
{
	stored_hunk(protocol_t p, network_key k, std::size_t s, int closer, bool local)
		: protocol(p), id(k), size(s), closer_peers(closer), local_requested(local),
		last_access(boost::posix_time::second_clock::universal_time()),
		stored(boost::posix_time::second_clock::universal_time())
	{}
	network_key id;
	boost::posix_time::ptime last_access;
	boost::posix_time::ptime stored;
	std::size_t size;
	int closer_peers;
	bool local_requested;
	protocol_t protocol;
};

typedef std::list<stored_hunk> stored_hunks_t;
typedef stored_hunks_t::iterator hunk_descriptor_t;

namespace detail
{
// We have to put the mapping in a base class to ensure that it is initialized before the region
struct mapped_content_base
{
	mapped_content_base(const std::string& path) : mapping(path.c_str(), read_write) {}
	file_mapping mapping;
};

class content_store_base;

}

struct mapped_content : ::detail::mapped_content_base, public mutable_shared_buffer
{
	friend class ::detail::content_store_base;

	typedef boost::shared_ptr<mapped_content> ptr;
	typedef boost::shared_ptr<const mapped_content> const_ptr;

	mapped_content(const std::string& path, std::size_t size)
		: ::detail::mapped_content_base(path), region(mapping, read_write, 0, size), deleted(false)
	{}

	mapped_content(const std::string& path, std::size_t size, bool temp)
		: ::detail::mapped_content_base(temp_path(path, size)), region(mapping, read_write, 0, size), deleted(true)
	{
		std::stringstream ss;
		ss << mapping.get_name() << '-' << std::hex << this;
		std::rename(mapping.get_name(), ss.str().c_str());
	}

	virtual mutable_buffer get() { return buffer(region.get_address(), region.get_size()); }
	virtual const_buffer get() const { return buffer(region.get_address(), region.get_size()); }

	~mapped_content()
	{
		if (deleted) {
			std::stringstream ss;
			ss << mapping.get_name() << '-' << std::hex << this;
			DLOG(INFO) << "deleting content " << ss.str().c_str();
			region.~mapped_region();
			mapping.~file_mapping();
#ifdef BOOST_WINDOWS
			::DeleteFileA(ss.str().c_str());
#else
			::unlink(ss.str().c_str());
#endif
		}
	}
private:
	mapped_region region;
	bool deleted;

	std::string temp_path(const std::string& path, std::size_t size);
};

struct stored_content
{
	stored_content(hunk_descriptor_t d) : desc(d) {}
	boost::weak_ptr<mapped_content> content;
	hunk_descriptor_t desc;
};

namespace detail
{

class content_store_base
{
public:
	mapped_content::ptr get_temp(std::size_t size);

protected:
	content_store_base(const std::string& path)
		: path_(path)
	{
	}

	std::string content_path(const network_key& key, bool create_dirs=false) const;
	stored_content do_load_content(boost::filesystem::directory_iterator file, protocol_t pid, local_node& node);
	const_payload_buffer_ptr do_get(stored_content& stored);
	mapped_content::const_ptr do_put(stored_content& stored, mapped_content::ptr content);
	mapped_content::const_ptr do_put(stored_content& stored, std::vector<const_buffer> content);
	void unlink_storage(stored_content& stored);
	void do_flush(stored_content& stored);

	std::string path_;
};

struct no_client_data {};

}

template <typename ClientHunkData = ::detail::no_client_data>
class content_store : public ::detail::content_store_base
{
	struct content_descriptor : public stored_content, public ClientHunkData
	{
		content_descriptor(stored_content c) : stored_content(c) {}
		ClientHunkData& client_data() const { return *this; }
	};

private:
	typedef std::map<network_key, content_descriptor> stored_contents_t;
	typedef typename stored_contents_t::iterator iterator;

public:
	typedef typename stored_contents_t::const_iterator const_iterator;

	content_store(const std::string& path, protocol_t pid, local_node& node)
		: content_store_base(path)
	{
		boost::filesystem::create_directories(boost::filesystem::path(path));
		load_contents(path_, pid, node);
	}

	~content_store()
	{
		flush();
	}

	void flush()
	{
		for (iterator content = stored_contents_.begin(); content != stored_contents_.end(); ++content)
			do_flush(content->second);
	}

	const_iterator begin() const { return stored_contents_.begin(); }
	const_iterator end() const { return stored_contents_.end(); }

	const_iterator stat(const network_key& key) { return stored_contents_.find(key); }

	const_payload_buffer_ptr get(const network_key& key)
	{
		iterator stored_contents = stored_contents_.find(key);

		if (stored_contents == stored_contents_.end())
			return const_payload_buffer_ptr();

		return do_get(stored_contents->second);
	}

	mapped_content::const_ptr put(hunk_descriptor_t desc, std::vector<const_buffer> content)
	{
		iterator stored_contents = stored_contents_.find(desc->id);

		if (stored_contents != stored_contents_.end()) {
			// On POSIX we should be using the rename to overwrite the existing file
			// But windows cannot handle that, so don't bother for now
			// This will only become an issue when we start doing multi-threading/processing
			unlink_storage(stored_contents->second);
		}
		else {
			stored_contents = stored_contents_.insert(std::make_pair(desc->id, stored_content(desc))).first;
		}

		stored_contents->second.desc = desc;

		return do_put(stored_contents->second, content);
	}

	mapped_content::const_ptr put(hunk_descriptor_t desc, mapped_content::ptr content)
	{
		iterator stored_contents = stored_contents_.find(desc->id);

		if (stored_contents != stored_contents_.end()) {
			// On POSIX we should be using the rename to overwrite the existing file
			// But windows cannot handle that, so don't bother for now
			// This will only become an issue when we start doing multi-threading/processing
			unlink_storage(stored_contents);
		}
		else {
			stored_contents = stored_contents_.insert(std::make_pair(desc->id, stored_content(desc))).first;
		}

		stored_contents->second.desc = desc;

		return do_put(stored_contents->second, content);
	}

	void unlink(const network_key& key)
	{
		iterator stored_contents = stored_contents_.find(key);
		unlink_storage(stored_contents->second);
		stored_contents_.erase(stored_contents);
	}

private:
	void load_contents(boost::filesystem::path dir_path, protocol_t pid, local_node& node)
	{
		if (!boost::filesystem::exists(dir_path)) return;
		boost::filesystem::directory_iterator end;
		for (boost::filesystem::directory_iterator it( dir_path ); it != end; ++it) {
			if (boost::filesystem::is_directory(it->status()))
				load_contents(it->path(), pid, node);
			else {
				network_key key(it->filename());
				stored_contents_.insert(std::make_pair(key, do_load_content(it, pid, node)));
			}
		}
	}

	stored_contents_t stored_contents_;
};

#endif