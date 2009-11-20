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

#include "hunk.hpp"
#include "config.hpp"
#include <boost/filesystem.hpp>
#include <boost/config.hpp>
#include <cstdio>

#ifdef BOOST_WINDOWS
// NTFS has an access time resolution of one hour (ugh)
static const content_store::file_time_t flush_threashold = 36000000000L;
#else
// flush file metadata at most every 10 minutes on POSIX systems
static const content_store::file_time_t flush_threashold = 600;
#include <sys/stat.h>
#include <utime.h>
#include <unistd.h>
#endif

using namespace boost::filesystem;

std::string content_store::mapped_content::temp_path(const std::string& path, std::size_t size)
{
	boost::filesystem::path p(path);
	std::stringstream ss;
	ss << std::hex << this;
	p /= ss.str();
#ifdef BOOST_WINDOWS
	HANDLE file_hnd = ::CreateFileA(p.string().c_str(), FILE_GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	::SetFilePointer(file_hnd, size, NULL, FILE_BEGIN);
	::SetEndOfFile(file_hnd);
	::CloseHandle(file_hnd);
#else
	::truncate(p.string().c_str(), size);
#endif
	return p.string();
}

static void load_contents(std::map<network_key, content_store::stored_content>& store, path dir_path)
{
	if (!exists(dir_path)) return;
	directory_iterator end;
	for (directory_iterator it( dir_path ); it != end; ++it) {
		if (is_directory(it->status()))
			load_contents(store, it->path());
		else {
			network_key key(it->filename());
			DLOG(INFO) << "loading content " << it->path().string().c_str();
			content_store::stored_content new_content;
#ifdef BOOST_WINDOWS
			HANDLE file_hnd = ::CreateFileA(it->path().string().c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			FILETIME stored, accessed;
			::GetFileTime(file_hnd, &stored, &accessed, NULL);
			LARGE_INTEGER temp;
			temp.LowPart = stored.dwLowDateTime;
			temp.HighPart = stored.dwHighDateTime;
			new_content.stored = temp.QuadPart;
			temp.LowPart = accessed.dwLowDateTime;
			temp.HighPart = accessed.dwHighDateTime;
			new_content.last_access = temp.QuadPart;
			new_content.size = ::GetFileSize(file_hnd, NULL);
			::CloseHandle(file_hnd);
#else
#endif
			store.insert(std::make_pair(key, new_content));
		}
	}

}

content_store::content_store(const std::string& path)
	: path_(path)
{
	boost::filesystem::create_directories(boost::filesystem::path(path));
	load_contents(stored_contents_, path_);
}

content_store::~content_store()
{
	flush();
}

void content_store::flush()
{
	file_time_t current_time = now();
	for (const_iterator content = begin(); content != end(); ++content)
		if (current_time - content->second.last_access > flush_threashold) {
			std::string path = content_path(content->first);
#ifdef BOOST_WINDOWS
			HANDLE file_hnd = ::CreateFileA(path.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			LARGE_INTEGER access_i;
			access_i.QuadPart = content->second.last_access;
			FILETIME last_access;
			last_access.dwLowDateTime = access_i.LowPart;
			last_access.dwHighDateTime = access_i.HighPart;
			::SetFileTime(file_hnd, NULL, &last_access, NULL);
			::CloseHandle(file_hnd);
#else
			utimbuf file_times;
			file_times.actime = content->second.last_access;
			file_times.modtime = content->second.stored;
			::utime(path.c_str(), &file_times);
#endif
		}
}

content_store::file_time_t content_store::now()
{
#ifdef BOOST_WINDOWS
	FILETIME sys_time;
	::GetSystemTimeAsFileTime(&sys_time);
	LARGE_INTEGER i;
	i.LowPart = sys_time.dwLowDateTime;
	i.HighPart = sys_time.dwHighDateTime;
	return i.QuadPart;
#else
	return ::time(NULL);
#endif
}

content_store::mapped_content_ptr content_store::get_temp(std::size_t size)
{
	return mapped_content_ptr(new mapped_content(path_, size, true));
}

content_store::const_mapped_content_ptr content_store::get(const network_key& key)
{
	iterator stored_contents = stored_contents_.find(key);

	if (stored_contents == stored_contents_.end())
		return const_mapped_content_ptr();

	const_mapped_content_ptr content = stored_contents->second.content.lock();
	
	if (content)
		return content;
	else {
		std::string path = content_path(key);
/*		std::size_t content_size;
#ifdef BOOST_WINDOWS
		HANDLE file_hnd = ::CreateFileA(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		content_size = ::GetFileSize(file_hnd, NULL);
		::CloseHandle(file_hnd);
#else
		stat content_stat;
		stat(path.c_str(), &content_stat);
		content_size = content_stat.st_size;
#endif */
		content.reset(new mapped_content(path, stored_contents->second.size));
		stored_contents->second.content = content;
		return content;
	}
}

content_store::const_mapped_content_ptr content_store::put(const network_key& key, const_buffer content)
{
	iterator stored_contents = stored_contents_.find(key);

	if (stored_contents != stored_contents_.end()) {
		unlink_storage(stored_contents);
	}
	else {
		stored_content new_content;
		stored_contents = stored_contents_.insert(std::make_pair(key, stored_content())).first;
	}

	stored_contents->second.last_access = now();
	stored_contents->second.stored = stored_contents->second.last_access;
	stored_contents->second.size = buffer_size(content);

	std::string path = content_path(key, true);

	{
#ifdef BOOST_WINDOWS
		HANDLE file_hnd = ::CreateFileA(path.c_str(), FILE_GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		::SetFilePointer(file_hnd, buffer_size(content), NULL, FILE_BEGIN);
		::SetEndOfFile(file_hnd);
		::CloseHandle(file_hnd);
#else
		::truncate(path.c_str(), buffer_size(content));
#endif
		file_mapping mapping(path.c_str(), read_write);
		mapped_region region(mapping, read_write, 0, buffer_size(content));
		std::memcpy(region.get_address(), buffer_cast<const void*>(content), buffer_size(content));
	}

	const_mapped_content_ptr new_mapping(new mapped_content(path, buffer_size(content)));
	stored_contents->second.content = new_mapping;
	return new_mapping;
}

content_store::const_mapped_content_ptr content_store::put(const network_key& key, content_store::mapped_content_ptr content)
{
	iterator stored_contents = stored_contents_.find(key);

	if (stored_contents != stored_contents_.end()) {
		// On POSIX we should be using the rename to overwrite the existing file
		// But windows cannot handle that, so don't bother for now
		// This will only become an issue when we start doing multi-threading/processing
		unlink_storage(stored_contents);
	}
	else {
		stored_content new_content;
		stored_contents = stored_contents_.insert(std::make_pair(key, stored_content())).first;
	}

	stored_contents->second.last_access = now();
	stored_contents->second.stored = stored_contents->second.last_access;
	stored_contents->second.size = content->region.get_size();
	content->deleted = false;

	std::stringstream temp_path;
	temp_path << content->mapping.get_name();
	temp_path << '-' << std::hex << content.get();

	// content *should* be unique at this point, should probably add a check for this...
	content.reset();
	
	std::string path = content_path(key, true);

	std::rename(temp_path.str().c_str(), path.c_str());

	const_mapped_content_ptr new_mapping(new mapped_content(path, stored_contents->second.size));
	stored_contents->second.content = new_mapping;
	return new_mapping;
}

void content_store::unlink(const network_key& key)
{
	iterator stored_contents = stored_contents_.find(key);
	unlink_storage(stored_contents);
	stored_contents_.erase(stored_contents);
}

void content_store::unlink_storage(iterator content)
{
#ifdef BOOST_WINDOWS
	// On Windows we must check for an active mapping and flag it if one exists
	// because Windows is braindamaged and can't unlink open files
	mapped_content_ptr mapped_content = boost::const_pointer_cast<content_store::mapped_content>(content->second.content.lock());
	if (mapped_content) {
		mapped_content->deleted = true;
		DLOG(INFO) << "unlinking storage " << mapped_content->mapping.get_name();
		// We can't delete the file but we can rename it, append the mapping object's address to the name
		// the mapping's destructor will delete it
		std::stringstream ss;
		ss << mapped_content->mapping.get_name() << '-' << std::hex << mapped_content.get();
		std::string old_name = mapped_content->mapping.get_name();
		std::string new_name = ss.str();
		::MoveFileA(mapped_content->mapping.get_name(), ss.str().c_str());
	}
	else {
		DLOG(INFO) << "deleteing content " << content_path(content->first).c_str();
		::DeleteFileA(content_path(content->first).c_str());
	}
#else
	::unlink(content_path(content->first).c_str());
#endif
}

std::string content_store::content_path(const network_key& key, bool create_dirs) const
{
	std::string key_str = key;
	boost::filesystem::path path(path_);
	path /= key_str.substr(0, 2);
	if (create_dirs)
		boost::filesystem::create_directories(path);
	path /= key_str;
	return path.string();
}
