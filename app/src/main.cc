// ensure_ssl_binding.cpp : Defines the entry point for the application.
//
#include <map>

#include <certificate_binding.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <CLI/CLI.hpp>

using namespace std;
using namespace spdlog::level;

int main(int argc, char** argv)
{
	CLI::App app{
		"Ensures the given certificate is bound to the given endpoint",
		"Ensure SSL Binding"
	};

	level_enum level{info};
	string endpoint;
	string hash;
	string appid;

	// enum mapper for loglevel
	map<string, level_enum> maplevel{
		{"error", err},
		{"warning", warn},
		{"trace", trace}};

	app.add_option("-e,--endpoint", endpoint, "The endpoint to check")
		->required();
	app.add_option("-H,--hash", hash, "The certificate hash to check")
		->required();
	app.add_option("-a,--appid", appid, "The appid to bind")
		->required();

	app.add_option("-v,--verbosity", level, "Log level")
		->transform(CLI::CheckedTransformer(maplevel, CLI::ignore_case));

	CLI11_PARSE(app, argc, argv);

	spdlog::set_level(level);
	auto console = spdlog::stdout_color_mt("App");
	auto binding = bindssl::CertificateBinding(endpoint, hash, appid);
	
	if (binding.CheckBinding()) {
		console->info("Binding is healthy");
	} else if (binding.Rebind()) {
		console->trace("Binding is unhealthy, attempting to repair");
		console->info("Rebind is healthy");
	} else {
		console->error("Binding is unhealthy and unrepairable");
		return 1;
	}

	return 0;
}
