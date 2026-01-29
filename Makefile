CXX = g++
CXXFLAGS = -std=c++23 -Iinclude -Wall
SPDLOGFLAGS = -lspdlog -lfmt
BOOSTFLAGS = -lpthread -lboost_system -lboost_thread
LOGGER = src/utils/Logger.cpp

SPDLOG_ACTIVE_LEVEL ?= SPDLOG_LEVEL_TRACE
SPDLOGFLAGS += -DSPDLOG_ACTIVE_LEVEL=$(SPDLOG_ACTIVE_LEVEL)

# --- config bootstrap (minimal) ---
APP_SETTINGS_HPP := include/app/settings.hpp
APP_SETTINGS_EX  := include/app/settings.hpp.example

$(APP_SETTINGS_HPP):
	@test -f "$@" || (cp "$(APP_SETTINGS_EX)" "$@" && echo "[GEN] $@ created from $(APP_SETTINGS_EX)")


all: $(APP_SETTINGS_HPP) app sim


app:
	g++ $(CXXFLAGS) $(LOGGER) src/app/http.cpp src/common/types.cpp src/app/energy_saving_app.cpp -o energy_saving_app $(BOOSTFLAGS) $(SPDLOGFLAGS)

sim:
	g++ $(CXXFLAGS) $(LOGGER) src/common/types.cpp src/sim/max_min_fairness.cpp src/sim/energy_saving_simulator.cpp -o energy_saving_simulator $(BOOSTFLAGS) $(SPDLOGFLAGS) -lssl -lcrypto
# 	Copy to the resgistered folder under simulation server
	cp ./energy_saving_simulator ../Simulation-platform-manager/registered/energy_saving_simulator/1.0/executable

clean:
	rm -f energy_saving_app energy_saving_simulator


