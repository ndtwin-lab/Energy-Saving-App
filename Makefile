CXX = g++
CXXFLAGS = -std=c++23 -Iinclude -Wall
SPDLOGFLAGS = -lspdlog -lfmt
BOOSTFLAGS = -lpthread -lboost_system -lboost_thread
LOGGER = src/utils/Logger.cpp

SPDLOG_ACTIVE_LEVEL ?= SPDLOG_LEVEL_TRACE
SPDLOGFLAGS += -DSPDLOG_ACTIVE_LEVEL=$(SPDLOG_ACTIVE_LEVEL)

all: app sim

app:
	g++ $(CXXFLAGS) $(LOGGER) src/app/http.cpp src/common/types.cpp src/app/power_app.cpp -o power_app $(BOOSTFLAGS) $(SPDLOGFLAGS)

sim:
	g++ $(CXXFLAGS) $(LOGGER) src/common/types.cpp src/sim/max_min_fairness.cpp src/sim/power_sim.cpp -o power_sim $(BOOSTFLAGS) $(SPDLOGFLAGS) -lssl -lcrypto
# 	Copy to the resgistered folder under simulation server
	cp ./power_sim ../NDT-Simulation-Server-master/registered/power_sim/1.0/executable

clean:
	rm -r power_app power_sim
