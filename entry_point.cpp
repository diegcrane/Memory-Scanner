
#include <windows.h>
#include <vector>
#include <iostream>

static const std::vector<std::pair<std::string, std::string>> detections
{
	{ "Check 1", "diegcrane" }
};

auto process_memory_region(std::string& region) -> void
{
	for (auto& detection : detections)
	{
		if (region.find(detection.second) != std::string::npos)
		{
			std::cout << detection.first << std::endl;
		}
	}
};

auto main() -> __int32
{
	unsigned long pid = 0;
	GetWindowThreadProcessId(FindWindowA("LWJGL", nullptr), &pid);

	auto prc_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

	if (prc_handle != nullptr)
	{
		std::vector<std::string> memory_regions;

		MEMORY_BASIC_INFORMATION mbi;

		for (unsigned __int64 base = 0; VirtualQueryEx(prc_handle, (void*)base, &mbi, sizeof(mbi)); base += mbi.RegionSize)
		{
			if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && mbi.Protect != PAGE_GUARD)
			{
				memory_regions.resize(memory_regions.size() + 1);
				memory_regions[memory_regions.size() - 1].resize(mbi.RegionSize, 0);

				ReadProcessMemory(prc_handle, (void*)base, &memory_regions[memory_regions.size() - 1][0], mbi.RegionSize, nullptr);
			}
		}

		std::vector<void*> threads;

		for (const auto& region : memory_regions)
		{
			threads.emplace_back(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)process_memory_region, (LPVOID)&region, 0, 0));
		}

		for (/*wait for threads to finish processing regions*/;; Sleep(10))
		{
			auto active = false;

			for (auto& thread : threads)
			{
				unsigned long exit_code = 0;

				GetExitCodeThread(thread, &exit_code);

				if (exit_code == STILL_ACTIVE)
					active = true;
			}
		
			if (!active)
				break;
		}

		std::cout << "scan completed" << std::endl;
	}
	else std::cout << "couldn't find/open process" << std::endl;

	return std::cin.get();
}