#include "config.hpp"
#include <fstream>
//#include <boost/filesystem.hpp>

namespace po = boost::program_options;

client_config config;

client_config::client_config()
{
	descriptions_.add_options()
		("port", po::value<unsigned short>(), "TCP port to listen on")
		("hunk_store_path", po::value<std::string>(), "Path to hunk storage")
		;


	std::ifstream config_file("client.conf");
	po::store(po::parse_config_file(config_file, descriptions_), variables_);
	po::notify(variables_);

	std::ifstream id_file("id");
	if (id_file.is_open()) {
		id_file >> std::hex;
		node_id_ = network_key(id_file);
	}
	else {
	}
}