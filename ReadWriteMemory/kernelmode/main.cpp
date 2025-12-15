#include <ntifs.h>

extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DiverName, PDRIVER_INITIALIZE InitializationFunction);
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAdress,
		PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize);
}

void debug_print(PCTSTR text) {
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
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

	NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	//note de implementat
	NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);

		debug_print("[*] device control apelat\n");

		NTSTATUS status = STATUS_UNSUCCESSFUL;

		PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);

		auto request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);

		//daca rahatul asta da fail crapa sistemul de operare 
		if (stack_irp == nullptr || request == nullptr) {
			debug_print("[!] eroare la obtinerea stack-ului irp\n");
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}

		//procesul de la care furam memorie 
		static PEPROCESS target_process = nullptr;

		const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;

		switch (control_code) {
		case codes::attach:
			status = PsLookupProcessByProcessId(
				request->process_id,
				&target_process
			);
			break;
		case codes::read:
			//fun fact asta poaate cauza blue screen :D  bag pula 
			if (target_process == nullptr) {
				status = MmCopyVirtualMemory(
					target_process,
					request->target,
					PsGetCurrentProcess(),
					request->buffer,
					request->size,
					KernelMode,
					&request->return_size
				);
				break;
			}
			break;
		case codes::write:
			if (target_process == nullptr) {
				status = MmCopyVirtualMemory(
					PsGetCurrentProcess(),
					request->buffer,
					target_process,
					request->target,
					request->size,
					KernelMode,
					&request->return_size
				);
			}
			break;
		default:
			break;
		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(Request);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return status;
	}

}


NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path_) {
	UNREFERENCED_PARAMETER(registry_path_);

	UNICODE_STRING device_name = {};
	RtlInitUnicodeString(&device_name, L"\\Device\\testdriver");

	PDEVICE_OBJECT device_object = nullptr;
	NTSTATUS status = IoCreateDevice(
		driver_object,
		0,
		&device_name,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&device_object
	);

	if (status != STATUS_SUCCESS) {
		debug_print("[!] eroare la crearea deviceului\n");
		return status;
	}

	debug_print("[*] device creat cu succes\n");

	UNICODE_STRING symbolic_link = {};
	RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\testdriver");
	status = IoCreateSymbolicLink(&symbolic_link, &device_name);
	if (status != STATUS_SUCCESS) {
		debug_print("[!] eroare la crearea symbolic link-ului\n");
		return status;
	}

	debug_print("[*] symbolic link creat cu succes\n");

	SetFlag(device_object->Flags, DO_BUFFERED_IO);

	driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

	ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);

	debug_print("[*] driver initializat cu succes\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry() {
	debug_print("[*] Dreptul la copiat este garantat de constitutie,Marcus Aurelius\n");

	UNICODE_STRING driver_name = {};
	RtlInitUnicodeString(&driver_name, L"\\Driver\\testdriver");
	return IoCreateDriver(&driver_name, &driver_main);
}
