// ensure_ssl_binding.cpp : Defines the entry point for the application.
//

#include <map>

#include "ensure_ssl_binding.h"

using namespace std;
using namespace ensure_ssl_binding;
using namespace spdlog::level;

int main(int argc, char** argv)
{
	CLI::App app{
		"Ensures the given certificate is bound to the given endpoint",
		"Ensure SSL Binding"
	};

	level_enum level{info};
	string endpoint = "0.0.0.0:44300";
	// string hash = "e635112919bdf5ca852723559d8a18813ae79ecd";
	string hash = "e635112919bdf5ca852723559d8a18813ae79ece";
	// string appid = "214124cd-d05b-4309-9af9-9caa44b2b74a";
	string appid = "214124cd-d05b-4309-9af9-9caa44b2b743";

	// enum mapper for loglevel
	map<string, level_enum> maplevel{{"error", err}, {"warning", warn}, {"trace", trace}};

	app.add_option("-e,--endpoint", endpoint, "The endpoint to check");
	app.add_option("-H,--hash", hash, "The certificate hash to check");
	app.add_option("-a,--appid", appid, "The appid to bind");

	app.add_option("-v,--verbosity", level, "Log level")
		->transform(CLI::CheckedTransformer(maplevel, CLI::ignore_case));

	CLI11_PARSE(app, argc, argv);

	spdlog::set_level(level);
	auto console = spdlog::stdout_color_mt("app");

	// The user has provided sufficient arguments, so we can proceed.
	if (!init_platform())
	{
		console->error("Failed platform initialization");
	}

	auto binding = query_binding(endpoint);
	if (binding->ensure(appid, hash))
	{
		console->info("Binding is healthy");
	}
	else
	{
		console->error("Binding is unhealthy and unrepairable");
	}

	cleanup_platform();
	return binding->is_valid() ? 0 : 1;
}
