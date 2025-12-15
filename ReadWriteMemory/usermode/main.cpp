#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

//capturam toate procesele din sistem de operare si vedem care e ala pe care il cautam noi cu while
static DWORD GetProcessIdByName(const wchar_t* process_name) {
	DWORD processId = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (snapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(decltype(processEntry));

	if (Process32FirstW(snapshot, &processEntry) == TRUE) {

		if (_wcsicmp(process_name, processEntry.szExeFile) == 0) {
			processId = processEntry.th32ProcessID;
		}
		else {
			while (Process32NextW(snapshot, &processEntry) == TRUE) {
				if (_wcsicmp(process_name, processEntry.szExeFile) == 0) {
					processId = processEntry.th32ProcessID;
					break;
				}
			}
		}
	}

	CloseHandle(snapshot);
	return processId;
}


//cu asta cautam modulele procesului la fel ca data trecut BTW modulele unui proces sunt dll uri,functi de runtime chiar si exe ul in sine practc poti cauta prin functiile lui
static std::uintptr_t get_module_base(const DWORD pid, const wchar_t* module_name) {
	std::uintptr_t module_base = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	MODULEENTRY32 moduleEntry = {};
	moduleEntry.dwSize = sizeof(decltype(moduleEntry));

	if (Module32FirstW(snapshot, &moduleEntry) == TRUE) {
		if (wcsstr(module_name, moduleEntry.szModule) != nullptr)
			module_base = reinterpret_cast<std::uintptr_t>(moduleEntry.modBaseAddr);
		else {
			while (Module32NextW(snapshot, &moduleEntry) == TRUE) {
				if (wcsstr(module_name, moduleEntry.szModule) != nullptr) {
					module_base = reinterpret_cast<std::uintptr_t>(moduleEntry.modBaseAddr);
					break;
				}
			}
		}
	}

	CloseHandle(snapshot);
	return module_base;
}
namespace driver {
	namespace codes {
		constexpr ULONG attach =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		constexpr ULONG read =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		constexpr ULONG write =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

	}

	//struct that communicate between kernel and user mode 
	struct Request {
		HANDLE process_id;

		PVOID target;
		PVOID buffer;

		SIZE_T size;
		SIZE_T return_size;
	};

	bool attach_to_process(HANDLE driver_handle, const DWORD pid) {
		Request request = {};
		request.process_id = reinterpret_cast<HANDLE>(pid);

		return DeviceIoControl(
			driver_handle,
			codes::attach,
			&request,
			sizeof(Request),
			&request,
			sizeof(Request),
			nullptr,
			nullptr
		);
	}

	template<class T>
	T read_memory(HANDLE driver_handle, const std::uintptr_t addr) {
		T temp = {};
		Request request;
		request.target = reinterpret_cast<PVOID>(addr);
		request.buffer = &temp;
		request.size = sizeof(T);
		DeviceIoControl(
			driver_handle,
			codes::read,
			&request,
			sizeof(Request),
			&request,
			sizeof(Request),
			nullptr,
			nullptr
		);
		return temp;
	}

	template <class T>
	void write_memory(HANDLE driver_handle, const std::uintptr_t addr, const T& value) {
		Request request;
		request.target = reinterpret_cast<PVOID>(addr);
		request.buffer = (PVOID)&value;
		request.size = sizeof(T);
		DeviceIoControl(
			driver_handle,
			codes::write,
			&request,
			sizeof(Request),
			&request,
			sizeof(Request),
			nullptr,
			nullptr
		);
	}
}

int main() {
	const DWORD pid = GetProcessIdByName(L"SafeExamBrowser.exe");
	if (pid == 0) {
		std::cout << "Failed to find process." << std::endl;
		std::cin.get();
		return 1;
	}

	const HANDLE driver = CreateFile(L"\\\\.\\testdriver",
		GENERIC_READ,
		0,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);

	if (driver == INVALID_HANDLE_VALUE) {
		std::cout << "Failed to open driver handle." << std::endl;
		std::cin.get();
		return 1;
	}

	if (driver::attach_to_process(driver, pid) == true) {
		std::cout << "Safe browser gasit" << std::endl;
	}
	auto ntdll_base = get_module_base(pid, L"ntdll.dll");
	if (ntdll_base == 0) {
		std::cout << "Failed to find ntdll module base" << std::endl;
	}
	else {
		std::cout << "ntdll base: " << std::hex << ntdll_base << std::dec << std::endl;
	}
	std::cin.get();

	CloseHandle(driver);

	return 0;
}
